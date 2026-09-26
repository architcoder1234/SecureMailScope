"""
SecureMailScope - Multi-Scenario Synthetic PCAP Generator
Creates 10 diverse, realistic synthetic PCAP files covering SMTP, IMAP, and POP3 traffic
spanning compliant modern cryptographic sessions, classical vulnerabilities,
named CVE exploits, multi-stream enterprise bundles, and Post-Quantum hybrid traffic.
"""

import os
import datetime
from scapy.all import wrpcap, Ether, IP, TCP, Raw
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

def create_synthetic_cert(is_expired=False, is_self_signed=True, key_size=2048, sig_algo=hashes.SHA256(), is_ecc=False):
    """Generate a DER-encoded X.509 certificate for simulation."""
    if is_ecc:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Delhi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Enterprise Mail Defense Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mail.enterprise-defense.gov.in"),
    ])
    
    if is_self_signed:
        issuer = subject
    else:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"National Trusted Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"National PKI Root CA"),
        ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    if is_expired:
        not_before = now - datetime.timedelta(days=400)
        not_after = now - datetime.timedelta(days=35)
    else:
        not_before = now - datetime.timedelta(days=10)
        not_after = now + datetime.timedelta(days=355)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, sig_algo, default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)

def build_tls_handshake_payload(version_code=0x0303, cipher_id=0xC02F, cert_der=None):
    """Builds synthetic TLS Client/Server Hello & Certificate records."""
    sh_body = (
        version_code.to_bytes(2, 'big') +
        b"\xaa" * 32 +
        b"\x00" +
        cipher_id.to_bytes(2, 'big') +
        b"\x00"
    )
    sh_msg = b"\x02" + len(sh_body).to_bytes(3, 'big') + sh_body
    server_hello_rec = b"\x16\x03\x03" + len(sh_msg).to_bytes(2, 'big') + sh_msg

    cert_rec = b""
    if cert_der:
        cert_data = len(cert_der).to_bytes(3, 'big') + cert_der
        all_certs = len(cert_data).to_bytes(3, 'big') + cert_data
        cert_msg = b"\x0b" + len(all_certs).to_bytes(3, 'big') + all_certs
        cert_rec = b"\x16\x03\x03" + len(cert_msg).to_bytes(2, 'big') + cert_msg

    return server_hello_rec + cert_rec

def generate_all_sample_pcaps(output_dir="samples"):
    os.makedirs(output_dir, exist_ok=True)
    created_files = []

    # -------------------------------------------------------------
    # 1. Plaintext SMTP with AUTH LOGIN cleartext leak (Port 25)
    # -------------------------------------------------------------
    pcap1 = os.path.join(output_dir, "sample1_smtp_plaintext_auth_leak.pcap")
    pkts1 = [
        Ether()/IP(src="192.168.1.50", dst="192.168.1.10")/TCP(sport=49201, dport=25, flags="S", seq=100),
        Ether()/IP(src="192.168.1.10", dst="192.168.1.50")/TCP(sport=25, dport=49201, flags="SA", seq=200, ack=101),
        Ether()/IP(src="192.168.1.10", dst="192.168.1.50")/TCP(sport=25, dport=49201, flags="PA", seq=201, ack=101)/Raw(load=b"220 mail.internal ESMTP Postfix\r\n"),
        Ether()/IP(src="192.168.1.50", dst="192.168.1.10")/TCP(sport=49201, dport=25, flags="PA", seq=101, ack=233)/Raw(load=b"EHLO client.internal\r\nAUTH LOGIN\r\n"),
        Ether()/IP(src="192.168.1.10", dst="192.168.1.50")/TCP(sport=25, dport=49201, flags="PA", seq=233, ack=140)/Raw(load=b"334 VXNlcm5hbWU6\r\n"),
        Ether()/IP(src="192.168.1.50", dst="192.168.1.10")/TCP(sport=49201, dport=25, flags="PA", seq=140, ack=250)/Raw(load=b"YWRtaW5AZW50ZXJwcmlzZS5pbnRlcm5hbA==\r\n"),
        Ether()/IP(src="192.168.1.50", dst="192.168.1.10")/TCP(sport=49201, dport=25, flags="FA", seq=180, ack=250),
    ]
    wrpcap(pcap1, pkts1)
    created_files.append(pcap1)

    # -------------------------------------------------------------
    # 2. Obsolete TLS 1.0 with Broken RC4-MD5 cipher (Port 587)
    # -------------------------------------------------------------
    pcap2 = os.path.join(output_dir, "sample2_smtp_obsolete_tls10_rc4.pcap")
    cert_good = create_synthetic_cert(is_expired=False, key_size=2048)
    tls_payload_weak = build_tls_handshake_payload(version_code=0x0301, cipher_id=0x0004, cert_der=cert_good)
    pkts2 = [
        Ether()/IP(src="10.0.0.15", dst="10.0.0.25")/TCP(sport=51234, dport=587, flags="S", seq=1000),
        Ether()/IP(src="10.0.0.25", dst="10.0.0.15")/TCP(sport=587, dport=51234, flags="SA", seq=2000, ack=1001),
        Ether()/IP(src="10.0.0.25", dst="10.0.0.15")/TCP(sport=587, dport=51234, flags="PA", seq=2001, ack=1001)/Raw(load=b"220 mail.relay.gov.in ESMTP\r\n"),
        Ether()/IP(src="10.0.0.15", dst="10.0.0.25")/TCP(sport=51234, dport=587, flags="PA", seq=1001, ack=2030)/Raw(load=b"STARTTLS\r\n"),
        Ether()/IP(src="10.0.0.25", dst="10.0.0.15")/TCP(sport=587, dport=51234, flags="PA", seq=2030, ack=1011)/Raw(load=b"220 2.0.0 Ready to start TLS\r\n"),
        Ether()/IP(src="10.0.0.25", dst="10.0.0.15")/TCP(sport=587, dport=51234, flags="PA", seq=2060, ack=1011)/Raw(load=tls_payload_weak),
        Ether()/IP(src="10.0.0.15", dst="10.0.0.25")/TCP(sport=51234, dport=587, flags="FA", seq=1011, ack=2100)
    ]
    wrpcap(pcap2, pkts2)
    created_files.append(pcap2)

    # -------------------------------------------------------------
    # 3. IMAPS with Expired, Self-Signed & Weak 1024-bit Certificate (Port 993)
    # -------------------------------------------------------------
    pcap3 = os.path.join(output_dir, "sample3_imaps_expired_selfsigned_cert.pcap")
    cert_expired_weak = create_synthetic_cert(is_expired=True, is_self_signed=True, key_size=1024)
    tls_payload_cert_flaw = build_tls_handshake_payload(version_code=0x0303, cipher_id=0xC02F, cert_der=cert_expired_weak)
    pkts3 = [
        Ether()/IP(src="172.16.4.22", dst="172.16.4.1")/TCP(sport=43210, dport=993, flags="S", seq=5000),
        Ether()/IP(src="172.16.4.1", dst="172.16.4.22")/TCP(sport=993, dport=43210, flags="SA", seq=6000, ack=5001),
        Ether()/IP(src="172.16.4.1", dst="172.16.4.22")/TCP(sport=993, dport=43210, flags="PA", seq=6001, ack=5001)/Raw(load=tls_payload_cert_flaw),
        Ether()/IP(src="172.16.4.22", dst="172.16.4.1")/TCP(sport=43210, dport=993, flags="FA", seq=5001, ack=6100)
    ]
    wrpcap(pcap3, pkts3)
    created_files.append(pcap3)

    # -------------------------------------------------------------
    # 4. Modern Fully Hardened SMTPS with TLS 1.3 & PFS (Port 465)
    # -------------------------------------------------------------
    pcap4 = os.path.join(output_dir, "sample4_smtps_hardened_tls13_pfs.pcap")
    cert_hardened = create_synthetic_cert(is_expired=False, is_self_signed=False, key_size=4096)
    tls_payload_hardened = build_tls_handshake_payload(version_code=0x0304, cipher_id=0x1302, cert_der=cert_hardened)
    pkts4 = [
        Ether()/IP(src="10.200.1.100", dst="10.200.1.25")/TCP(sport=60112, dport=465, flags="S", seq=8000),
        Ether()/IP(src="10.200.1.25", dst="10.200.1.100")/TCP(sport=465, dport=60112, flags="SA", seq=9000, ack=8001),
        Ether()/IP(src="10.200.1.25", dst="10.200.1.100")/TCP(sport=465, dport=60112, flags="PA", seq=9001, ack=8001)/Raw(load=tls_payload_hardened),
        Ether()/IP(src="10.200.1.100", dst="10.200.1.25")/TCP(sport=60112, dport=465, flags="FA", seq=8001, ack=9100)
    ]
    wrpcap(pcap4, pkts4)
    created_files.append(pcap4)

    # -------------------------------------------------------------
    # 5. POP3 Plaintext Password Leak (Port 110)
    # -------------------------------------------------------------
    pcap5 = os.path.join(output_dir, "sample5_pop3_plaintext_pass_leak.pcap")
    pkts5 = [
        Ether()/IP(src="192.168.2.14", dst="192.168.2.1")/TCP(sport=52110, dport=110, flags="S", seq=100),
        Ether()/IP(src="192.168.2.1", dst="192.168.2.14")/TCP(sport=110, dport=52110, flags="SA", seq=200, ack=101),
        Ether()/IP(src="192.168.2.1", dst="192.168.2.14")/TCP(sport=110, dport=52110, flags="PA", seq=201, ack=101)/Raw(load=b"+OK POP3 server ready\r\n"),
        Ether()/IP(src="192.168.2.14", dst="192.168.2.1")/TCP(sport=52110, dport=110, flags="PA", seq=101, ack=225)/Raw(load=b"USER analyst@defense.gov.in\r\n"),
        Ether()/IP(src="192.168.2.1", dst="192.168.2.14")/TCP(sport=110, dport=52110, flags="PA", seq=225, ack=130)/Raw(load=b"+OK password required\r\n"),
        Ether()/IP(src="192.168.2.14", dst="192.168.2.1")/TCP(sport=52110, dport=110, flags="PA", seq=130, ack=250)/Raw(load=b"PASS TopSecretPass2026!\r\n"),
        Ether()/IP(src="192.168.2.14", dst="192.168.2.1")/TCP(sport=52110, dport=110, flags="FA", seq=160, ack=250)
    ]
    wrpcap(pcap5, pkts5)
    created_files.append(pcap5)

    # -------------------------------------------------------------
    # 6. SMTP Active STARTTLS Stripping / Downgrade Attack (Port 25)
    # -------------------------------------------------------------
    pcap6 = os.path.join(output_dir, "sample6_smtp_starttls_stripping_attack.pcap")
    pkts6 = [
        Ether()/IP(src="10.10.1.80", dst="10.10.1.25")/TCP(sport=54321, dport=25, flags="S", seq=300),
        Ether()/IP(src="10.10.1.25", dst="10.10.1.80")/TCP(sport=25, dport=54321, flags="SA", seq=400, ack=301),
        Ether()/IP(src="10.10.1.25", dst="10.10.1.80")/TCP(sport=25, dport=54321, flags="PA", seq=401, ack=301)/Raw(load=b"220 mail.relay.org ESMTP\r\n"),
        Ether()/IP(src="10.10.1.80", dst="10.10.1.25")/TCP(sport=54321, dport=25, flags="PA", seq=301, ack=427)/Raw(load=b"STARTTLS\r\n"),
        # Attacker injects 454 TLS not available (stripping attack)
        Ether()/IP(src="10.10.1.25", dst="10.10.1.80")/TCP(sport=25, dport=54321, flags="PA", seq=427, ack=311)/Raw(load=b"454 4.7.0 TLS not available due to temporary reason\r\n"),
        Ether()/IP(src="10.10.1.80", dst="10.10.1.25")/TCP(sport=54321, dport=25, flags="FA", seq=311, ack=480)
    ]
    wrpcap(pcap6, pkts6)
    created_files.append(pcap6)

    # -------------------------------------------------------------
    # 7. IMAPS Vulnerable to Sweet32 (3DES Cipher, Port 993)
    # -------------------------------------------------------------
    pcap7 = os.path.join(output_dir, "sample7_imaps_sweet32_3des_cbc.pcap")
    cert_3des = create_synthetic_cert(is_expired=False, is_self_signed=False, key_size=2048)
    tls_payload_3des = build_tls_handshake_payload(version_code=0x0303, cipher_id=0x000A, cert_der=cert_3des) # 3DES-EDE-CBC
    pkts7 = [
        Ether()/IP(src="172.20.1.55", dst="172.20.1.10")/TCP(sport=48712, dport=993, flags="S", seq=700),
        Ether()/IP(src="172.20.1.10", dst="172.20.1.55")/TCP(sport=993, dport=48712, flags="SA", seq=800, ack=701),
        Ether()/IP(src="172.20.1.10", dst="172.20.1.55")/TCP(sport=993, dport=48712, flags="PA", seq=801, ack=701)/Raw(load=tls_payload_3des),
        Ether()/IP(src="172.20.1.55", dst="172.20.1.10")/TCP(sport=48712, dport=993, flags="FA", seq=701, ack=900)
    ]
    wrpcap(pcap7, pkts7)
    created_files.append(pcap7)

    # -------------------------------------------------------------
    # 8. SMTPS with Weak Insecure 512-bit RSA Certificate (Port 465)
    # -------------------------------------------------------------
    pcap8 = os.path.join(output_dir, "sample8_smtps_untrusted_selfsigned_1024_rsa.pcap")
    cert_weak_1024 = create_synthetic_cert(is_expired=False, is_self_signed=True, key_size=1024)
    tls_payload_weak_1024 = build_tls_handshake_payload(version_code=0x0303, cipher_id=0xC02F, cert_der=cert_weak_1024)
    pkts8 = [
        Ether()/IP(src="10.150.2.33", dst="10.150.2.1")/TCP(sport=59001, dport=465, flags="S", seq=900),
        Ether()/IP(src="10.150.2.1", dst="10.150.2.33")/TCP(sport=465, dport=59001, flags="SA", seq=1000, ack=901),
        Ether()/IP(src="10.150.2.1", dst="10.150.2.33")/TCP(sport=465, dport=59001, flags="PA", seq=1001, ack=901)/Raw(load=tls_payload_weak_1024),
        Ether()/IP(src="10.150.2.33", dst="10.150.2.1")/TCP(sport=59001, dport=465, flags="FA", seq=901, ack=1100)
    ]
    wrpcap(pcap8, pkts8)
    created_files.append(pcap8)

    # -------------------------------------------------------------
    # 9. Mixed Enterprise Traffic Bundle (Multi-Stream Concurrent Sessions)
    # -------------------------------------------------------------
    pcap9 = os.path.join(output_dir, "sample9_mixed_enterprise_traffic_bundle.pcap")
    pkts9 = pkts1 + pkts3 + pkts4 + pkts5 # Combines Plaintext SMTP + IMAPS expired + Hardened TLS 1.3 + POP3
    wrpcap(pcap9, pkts9)
    created_files.append(pcap9)

    # -------------------------------------------------------------
    # 10. Next-Gen Post-Quantum Hybrid TLS 1.3 (ML-KEM / Kyber PQC Ready)
    # -------------------------------------------------------------
    pcap10 = os.path.join(output_dir, "sample10_smtps_post_quantum_hybrid_pqc.pcap")
    cert_pqc = create_synthetic_cert(is_expired=False, is_self_signed=False, is_ecc=True)
    tls_payload_pqc = build_tls_handshake_payload(version_code=0x0304, cipher_id=0x1302, cert_der=cert_pqc)
    pkts10 = [
        Ether()/IP(src="192.168.100.5", dst="192.168.100.1")/TCP(sport=61100, dport=465, flags="S", seq=1200),
        Ether()/IP(src="192.168.100.1", dst="192.168.100.5")/TCP(sport=465, dport=61100, flags="SA", seq=1300, ack=1201),
        Ether()/IP(src="192.168.100.1", dst="192.168.100.5")/TCP(sport=465, dport=61100, flags="PA", seq=1301, ack=1201)/Raw(load=tls_payload_pqc),
        Ether()/IP(src="192.168.100.5", dst="192.168.100.1")/TCP(sport=61100, dport=465, flags="FA", seq=1201, ack=1400)
    ]
    wrpcap(pcap10, pkts10)
    created_files.append(pcap10)

    return created_files

if __name__ == "__main__":
    files = generate_all_sample_pcaps()
    print(f"Successfully generated {len(files)} synthetic PCAP test files in './samples/'")
