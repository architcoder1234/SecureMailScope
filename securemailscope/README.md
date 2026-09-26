# SecureMailScope

AI-assisted passive cryptographic security posture assessment for SMTP/IMAP/POP3
email traffic captured in PCAP files. Built for NTRO problem statement #26159.

## What it does
1. Reassembles TCP streams from a PCAP.
2. Detects SMTP/IMAP/POP3 sessions and locates STARTTLS/STLS upgrades (or implicit TLS on 465/993/995).
3. Passively parses the TLS handshake (ClientHello/ServerHello/Certificate) — no decryption, no keys needed.
4. Extracts and validates X.509 certificates (expiry, key strength, signature algorithm, self-signed).
5. Scores each session with explainable rules + an ML anomaly layer (IsolationForest).
6. Serves results via a FastAPI backend and a browser dashboard, with JSON/HTML/PDF export.

## Setup

```bash
cd securemailscope
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

> PDF export needs WeasyPrint's system libraries (pango, cairo, gdk-pixbuf).
> If you don't want to install those, JSON/HTML export still work with no extra setup.

## Run

```bash
uvicorn backend.app.main:app --reload --port 8000
```

Open http://localhost:8000 — upload a `.pcap`/`.pcapng` and click **Analyze PCAP**.

## Generating test PCAPs (per the problem statement's dataset note)

Since NTRO's dataset is synthetic/participant-generated, capture your own traffic:

```bash
# Terminal 1: start capture
sudo tcpdump -i lo -w test_smtp.pcap port 25 or port 587 or port 465

# Terminal 2: send test mail via a local dev SMTP server (e.g. MailHog, Postfix in a
# container, or Python's smtpd/aiosmtpd) using STARTTLS or implicit TLS (465)
```

Do the same for IMAP (143/993) and POP3 (110/995) using Dovecot, GreenMail, or similar.
Include a mix of: modern config (TLS 1.2/1.3, ECDHE, valid certs), and deliberately
weak config (TLS 1.0, RC4/3DES, expired/self-signed certs, no STARTTLS) so the
tool has something interesting to flag.

## Project structure

```
securemailscope/
├── backend/app/
│   ├── core/
│   │   ├── pipeline.py          # orchestrates the full analysis
│   │   ├── protocol_detector.py # SMTP/IMAP/POP3 + STARTTLS detection
│   │   ├── tls_handshake.py     # passive TLS record/handshake parser
│   │   ├── cert_analyzer.py     # X.509 validation
│   │   ├── risk_engine.py       # rule-based scoring + IsolationForest anomaly layer
│   │   └── report_generator.py  # JSON/HTML/PDF export
│   ├── utils/tcp_reassembly.py  # PCAP → ordered bidirectional TCP streams
│   ├── models/schemas.py        # Pydantic response models
│   ├── api/routes.py            # /api/analyze, /api/report/*
│   └── main.py                  # FastAPI app
├── frontend/index.html          # single-page dashboard (Chart.js)
├── data/sample_pcaps/           # put your generated test captures here
├── docs/architecture.md
└── requirements.txt
```

## Known limitations (be upfront about these in your pitch/demo)

- **TLS 1.3**: the Certificate message is encrypted, so certificate-level checks
  only work for TLS 1.2 and earlier (and implicit-TLS sessions negotiating ≤1.2).
  Version/cipher detection from ServerHello still works for 1.3.
- **Handshake message fragmentation**: the parser assumes ClientHello/ServerHello/
  Certificate each fit within a small number of TCP segments reassembled in order;
  extremely fragmented captures may need a more robust TLS record reassembler
  (this is a good "if we had more time" talking point for judges).
- **ML layer is unsupervised** (IsolationForest) since no labeled dataset exists
  yet. `risk_engine.train_supervised()` is stubbed in for when you have labeled
  synthetic sessions.

## Roadmap / next steps to extend this into the full deliverable list

- [ ] Certificate chain validation against a trust store (currently checks leaf cert only)
- [ ] SQLite persistence for session history across multiple PCAP uploads
- [ ] Batch/folder upload for analyzing multiple captures at once
- [ ] React/TS dashboard (swap in for `frontend/index.html`) with filtering/sorting
- [ ] Supervised ML model once labeled sessions are available
- [ ] STARTTLS stripping / downgrade-attack detection (compare offered vs. used encryption)
