# Architecture Notes

## Data flow

```
PCAP file
  └─▶ scapy rdpcap → per-packet IP/TCP layers
        └─▶ tcp_reassembly.reassemble_streams()
              groups packets into TCPStream objects keyed by normalized 4-tuple,
              ordered by timestamp, split into client→server / server→client byte streams
                └─▶ protocol_detector.detect_protocol()
                      matches well-known ports (25/587/465/143/993/110/995),
                      scans plaintext bytes for STARTTLS/STLS command + server ACK,
                      records the byte offset where TLS begins in each direction
                        └─▶ tls_handshake.parse_handshake() (called once per direction)
                              walks TLS record layer (5-byte header: type/version/length),
                              walks handshake messages within records (4-byte header: type/length),
                              extracts ClientHello (offered ciphers, version) and
                              ServerHello (negotiated version/cipher, supported_versions ext for TLS1.3)
                              and Certificate message (raw DER certs, TLS ≤1.2 only)
                                └─▶ cert_analyzer.analyze_certificates()
                                      cryptography.x509 parses DER → checks expiry, self-signed,
                                      key type/size, signature algorithm
                                        └─▶ risk_engine.evaluate_session_rules()
                                              explainable rule checks → Finding list → base_score
                                            risk_engine.apply_anomaly_detection()
                                              IsolationForest over per-session feature vectors →
                                              anomaly_score, blended into final_score/risk_label
                                                └─▶ report_generator (JSON/HTML/PDF)
                                                └─▶ FastAPI /api/analyze response → dashboard
```

## Why passive (no decryption)

The framework never needs the server's private key or session keys. TLS handshake
messages up through ServerHello (and Certificate, pre-TLS 1.3) are sent in the
clear specifically so a passive observer *can* verify what was negotiated — this
is exactly the surface this tool inspects. Nothing here decrypts application data.

## Test data generation

`backend/tests/e2e_test.py` demonstrates a repeatable way to generate realistic
test captures without root/tcpdump access:
1. Spin up a real `openssl s_server` (self-signed cert, chosen TLS version/cipher).
2. Run a loopback TCP proxy that forwards bytes between a test client and the
   real server while logging each direction's raw bytes.
3. Trigger the handshake with `openssl s_client`.
4. Prepend synthetic plaintext SMTP/IMAP/POP3 + STARTTLS bytes (for protocol
   detection) to the real captured TLS bytes.
5. Build scapy `IP()/TCP()/Raw()` packets from the logged byte segments and
   `wrpcap()` them into a `.pcap`.

This gives you *genuine* TLS handshake bytes (real ServerHello, real
certificate DER, real cipher negotiation) to validate the parser against,
while letting you control the version/cipher/cert conditions per test case —
useful for building your "known-bad" test fixtures (TLS 1.0, RC4, expired
certs, no STARTTLS at all) alongside "known-good" ones.

For a full demo dataset, repeat this for IMAP (Dovecot or a raw `openssl
s_server` on 993) and POP3 (995), and for a no-STARTTLS/downgrade case (send
the STARTTLS command but never actually negotiate TLS — the rule engine's
"plaintext" and "downgrade" checks should catch this).

## Extension points

- `risk_engine.train_supervised()` — swap in a labeled RandomForest once you
  have enough categorized sessions from your generated dataset.
- `cert_analyzer.py` — currently validates the leaf certificate only; add
  chain-of-trust validation against a CA bundle for the "certificate chain
  validation" deliverable.
- `tls_handshake.py` — the record/handshake walkers assume each message is
  reassembled from ordered TCP payload concatenation; for very fragmented
  captures, add explicit TCP sequence-number-based reassembly instead of
  simple concatenation (currently `TCPStream.client_bytes()` just joins
  payloads in timestamp order, which is correct for the vast majority of
  captures but not provably correct under packet reordering/retransmission).
