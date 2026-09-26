"""
SecureMailScope - Network Forensics & TLS/X.509 Cryptographic Analyzer
Dissects PCAP files, tracks TCP streams, identifies SMTP/IMAP/POP3,
parses TLS Handshakes, and extracts X.509 Certificate Chains.
"""

import os
import datetime
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP, IPv6, Raw
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ciphers_db

EMAIL_PORTS = {
    25: ("SMTP", "Plaintext/STARTTLS"),
    587: ("SMTP Submission", "STARTTLS"),
    465: ("SMTPS", "Implicit TLS"),
    143: ("IMAP", "Plaintext/STARTTLS"),
    993: ("IMAPS", "Implicit TLS"),
    110: ("POP3", "Plaintext/STARTTLS"),
    995: ("POP3S", "Implicit TLS")
}

class MailStreamAnalyzer:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.sessions = []
        self.summary_stats = {
            "total_packets": 0,
            "total_email_sessions": 0,
            "smtp_sessions": 0,
            "imap_sessions": 0,
            "pop3_sessions": 0,
            "plaintext_sessions": 0,
            "starttls_sessions": 0,
            "implicit_tls_sessions": 0,
            "tls_versions": defaultdict(int),
            "weak_ciphers_detected": 0,
            "cert_issues_detected": 0
        }

    def parse(self):
        """Read and process packets from PCAP file."""
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        packets = rdpcap(self.pcap_path)
        self.summary_stats["total_packets"] = len(packets)

        # Group packets into 4-tuple TCP streams: (src_ip, src_port, dst_ip, dst_port)
        tcp_streams = defaultdict(list)
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                sport, dport = tcp_layer.sport, tcp_layer.dport
                
                # Check if involves standard or likely email ports
                if sport in EMAIL_PORTS or dport in EMAIL_PORTS:
                    # Normalize session key (unordered pair of endpoints)
                    s_key = tuple(sorted([(ip_layer.src, sport), (ip_layer.dst, dport)]))
                    tcp_streams[s_key].append(pkt)

        # Analyze each stream
        session_id = 1
        for s_endpoints, s_packets in tcp_streams.items():
            session_info = self._analyze_stream(session_id, s_endpoints, s_packets)
            if session_info:
                self.sessions.append(session_info)
                session_id += 1

        self.summary_stats["total_email_sessions"] = len(self.sessions)
        return self.sessions, self.summary_stats

    def _analyze_stream(self, session_id: int, endpoints, packets):
        ep1, ep2 = endpoints
        # Identify server and client
        server_port = ep1[1] if ep1[1] in EMAIL_PORTS else ep2[1]
        server_ip = ep1[0] if ep1[1] in EMAIL_PORTS else ep2[0]
        client_ip = ep2[0] if ep1[1] in EMAIL_PORTS else ep1[0]
        client_port = ep2[1] if ep1[1] in EMAIL_PORTS else ep1[1]

        proto_name, expected_mode = EMAIL_PORTS.get(server_port, ("Unknown Email", "Unknown"))
        
        # Track statistics
        if "SMTP" in proto_name:
            self.summary_stats["smtp_sessions"] += 1
        elif "IMAP" in proto_name:
            self.summary_stats["imap_sessions"] += 1
        elif "POP3" in proto_name:
            self.summary_stats["pop3_sessions"] += 1

        # Reconstruct TCP stream payloads
        client_payload = b""
        server_payload = b""
        raw_combined = []

        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)

        for pkt in packets:
            if Raw in pkt:
                payload = pkt[Raw].load
                raw_combined.append(payload)
                if pkt[IP].src == client_ip:
                    client_payload += payload
                else:
                    server_payload += payload

        # Check for STARTTLS vs Plaintext vs Implicit TLS
        encryption_mode = "Plaintext"
        starttls_detected = False
        starttls_success = False

        combined_text = b"".join(raw_combined)
        
        # Detect STARTTLS negotiation signatures in plain text
        if b"STARTTLS" in combined_text or b"STLS" in combined_text:
            starttls_detected = True
            # Inspect TLS handshake presence
            tls_info = self._extract_tls_details(raw_combined)
            if (b"220 2.0.0" in server_payload or b"+OK Begin TLS" in server_payload or b". OK" in server_payload) and tls_info.get("has_tls"):
                starttls_success = True
                encryption_mode = "STARTTLS Upgraded"
            else:
                encryption_mode = "STARTTLS Failed/Stripped"
        elif expected_mode == "Implicit TLS":
            encryption_mode = "Implicit TLS"
        else:
            encryption_mode = "Plaintext"

        if encryption_mode == "Plaintext":
            self.summary_stats["plaintext_sessions"] += 1
        elif "STARTTLS" in encryption_mode:
            self.summary_stats["starttls_sessions"] += 1
        elif encryption_mode == "Implicit TLS":
            self.summary_stats["implicit_tls_sessions"] += 1

        # Inspect TLS Handshakes and Certificates
        tls_info = self._extract_tls_details(raw_combined)

        # Check credentials leakage if plaintext
        auth_leak = self._detect_plaintext_auth(client_payload)

        return {
            "session_id": session_id,
            "protocol": proto_name,
            "client": f"{client_ip}:{client_port}",
            "server": f"{server_ip}:{server_port}",
            "packet_count": len(packets),
            "duration_sec": round(end_time - start_time, 3),
            "encryption_mode": encryption_mode,
            "starttls_negotiated": starttls_detected,
            "starttls_success": starttls_success,
            "plaintext_auth_leaked": auth_leak,
            "tls_details": tls_info
        }

    def _detect_plaintext_auth(self, client_payload: bytes):
        """Check for cleartext authentication credentials in commands."""
        indicators = []
        payload_lower = client_payload.lower()
        if b"auth login" in payload_lower or b"auth plain" in payload_lower:
            indicators.append("SMTP AUTH in cleartext detected")
        if b"login " in payload_lower:
            indicators.append("IMAP/POP3 LOGIN user/pass in cleartext")
        if b"pass " in payload_lower:
            indicators.append("POP3 PASS command in cleartext")
        return indicators

    def _extract_tls_details(self, payloads):
        """Dissect TLS records across payload segments."""
        tls_data = {
            "has_tls": False,
            "client_version": None,
            "negotiated_version": None,
            "sni": None,
            "cipher_suite": None,
            "key_exchange": None,
            "forward_secrecy": False,
            "certificates": [],
            "issues": []
        }

        for chunk in payloads:
            rec_idx = 0
            while rec_idx + 5 <= len(chunk):
                record_type = chunk[rec_idx]
                if record_type in [0x14, 0x15, 0x16, 0x17]:
                    rec_ver = (chunk[rec_idx+1] << 8) | chunk[rec_idx+2]
                    rec_len = (chunk[rec_idx+3] << 8) | chunk[rec_idx+4]
                    rec_end = min(len(chunk), rec_idx + 5 + rec_len)

                    if record_type == 0x16:  # TLS Handshake Record
                        tls_data["has_tls"] = True
                        idx = rec_idx + 5
                        while idx + 4 <= rec_end:
                            msg_type = chunk[idx]
                            msg_len = (chunk[idx+1] << 16) | (chunk[idx+2] << 8) | chunk[idx+3]
                            msg_body = chunk[idx+4 : idx+4+msg_len]

                            if msg_type == 1:  # Client Hello
                                if len(msg_body) >= 34:
                                    cli_ver = (msg_body[0] << 8) | msg_body[1]
                                    tls_data["client_version"] = ciphers_db.lookup_tls_version(cli_ver)
                                    self._extract_sni(msg_body, tls_data)

                            elif msg_type == 2:  # Server Hello
                                if len(msg_body) >= 35:
                                    srv_ver = (msg_body[0] << 8) | msg_body[1]
                                    sess_id_len = msg_body[34]
                                    cipher_offset = 35 + sess_id_len
                                    cipher_id = 0
                                    if len(msg_body) >= cipher_offset + 2:
                                        cipher_id = (msg_body[cipher_offset] << 8) | msg_body[cipher_offset+1]
                                    
                                    actual_ver = srv_ver
                                    tls_ver_info = ciphers_db.lookup_tls_version(actual_ver)
                                    tls_data["negotiated_version"] = tls_ver_info
                                    self.summary_stats["tls_versions"][tls_ver_info["name"]] += 1
                                    
                                    cipher_info = ciphers_db.lookup_cipher(cipher_id)
                                    tls_data["cipher_suite"] = cipher_info
                                    tls_data["key_exchange"] = cipher_info["key_exchange"]
                                    tls_data["forward_secrecy"] = cipher_info["forward_secrecy"]

                                    if cipher_info["rating"] in ["Warning", "Critical"]:
                                        self.summary_stats["weak_ciphers_detected"] += 1
                                        tls_data["issues"].append(f"Insecure Cipher: {cipher_info['name']} ({cipher_info['notes']})")

                            elif msg_type == 11:  # Certificate Message
                                certs = self._parse_certificates(msg_body)
                                tls_data["certificates"].extend(certs)

                            idx += 4 + msg_len
                    rec_idx = rec_end
                else:
                    rec_idx += 1

        return tls_data

    def _extract_sni(self, body: bytes, tls_data: dict):
        """Extract Server Name Indication (SNI) from Client Hello extensions."""
        try:
            sess_id_len = body[34]
            offset = 35 + sess_id_len
            if offset + 2 > len(body):
                return
            cipher_len = (body[offset] << 8) | body[offset+1]
            offset += 2 + cipher_len
            if offset + 1 > len(body):
                return
            comp_len = body[offset]
            offset += 1 + comp_len
            if offset + 2 > len(body):
                return
            ext_len = (body[offset] << 8) | body[offset+1]
            offset += 2
            
            while offset + 4 <= len(body):
                ext_type = (body[offset] << 8) | body[offset+1]
                e_len = (body[offset+2] << 8) | body[offset+3]
                if ext_type == 0:  # SNI
                    sni_bytes = body[offset+4 : offset+4+e_len]
                    if len(sni_bytes) > 5:
                        sni_name_len = (sni_bytes[3] << 8) | sni_bytes[4]
                        sni_name = sni_bytes[5:5+sni_name_len].decode('utf-8', errors='ignore')
                        tls_data["sni"] = sni_name
                offset += 4 + e_len
        except Exception:
            pass

    def _parse_certificates(self, cert_payload: bytes):
        """Parse raw ASN.1 DER certificates and evaluate X.509 security hygiene."""
        parsed_certs = []
        if len(cert_payload) < 3:
            return parsed_certs

        all_certs_len = (cert_payload[0] << 16) | (cert_payload[1] << 8) | cert_payload[2]
        idx = 3
        while idx + 3 <= len(cert_payload) and idx < all_certs_len + 3:
            c_len = (cert_payload[idx] << 16) | (cert_payload[idx+1] << 8) | cert_payload[idx+2]
            idx += 3
            der_data = cert_payload[idx : idx + c_len]
            idx += c_len

            try:
                cert = x509.load_der_x509_certificate(der_data, default_backend())
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                
                # Validity dates
                try:
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                except AttributeError:
                    not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                    not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

                now = datetime.datetime.now(datetime.timezone.utc)
                is_expired = now > not_after
                is_not_yet_valid = now < not_before
                is_self_signed = (subject == issuer)

                # Public key inspection
                pub_key = cert.public_key()
                key_algo = pub_key.__class__.__name__
                key_size = getattr(pub_key, "key_size", "Unknown")
                
                # Signature algorithm
                sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"

                issues = []
                if is_expired:
                    issues.append("Certificate Expired")
                if is_not_yet_valid:
                    issues.append("Certificate Not Yet Valid")
                if "EllipticCurve" in key_algo or "ec" in key_algo.lower():
                    if isinstance(key_size, int) and key_size < 224:
                        issues.append(f"Weak ECC Key Size: {key_size} bits (Minimum recommended: 256-bit ECC / P-256)")
                elif isinstance(key_size, int) and key_size < 2048:
                    issues.append(f"Weak RSA Key Size: {key_size} bits (Minimum recommended: 2048-bit RSA)")
                if sig_algo.lower() in ["md5", "sha1"]:
                    issues.append(f"Insecure Signature Algorithm ({sig_algo.upper()})")

                if issues:
                    self.summary_stats["cert_issues_detected"] += 1

                parsed_certs.append({
                    "subject": subject,
                    "issuer": issuer,
                    "is_self_signed": is_self_signed,
                    "is_expired": is_expired,
                    "valid_from": str(not_before.date()),
                    "valid_to": str(not_after.date()),
                    "key_algorithm": key_algo,
                    "key_size": key_size,
                    "signature_algorithm": sig_algo.upper(),
                    "issues": issues,
                    "serial_number": hex(cert.serial_number)
                })
            except Exception as e:
                parsed_certs.append({
                    "subject": "Parse Error",
                    "issuer": "Parse Error",
                    "issues": [f"Malformed X.509: {str(e)}"]
                })

        return parsed_certs
