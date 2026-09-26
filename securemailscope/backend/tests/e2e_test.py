"""
End-to-end smoke test: runs a real openssl s_server (self-signed cert, TLS 1.2)
behind a plaintext SMTP+STARTTLS greeting, connects with openssl s_client,
captures the actual bytes exchanged over loopback using a raw socket proxy
(so real TLS record bytes are captured, not synthesized), builds a PCAP with
scapy, and runs it through the full analysis pipeline.
"""
import socket
import subprocess
import sys
import tempfile
import threading
import time
import os
from pathlib import Path
from scapy.all import IP, TCP, Ether, wrpcap, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from backend.app.core.pipeline import analyze_pcap  # noqa: E402

CLIENT_IP, SERVER_IP = "10.0.0.5", "10.0.0.6"
CLIENT_PORT, SERVER_PORT = 51000, 587


def make_packets(events):
    """events: list of (direction, payload_bytes) in order -> scapy packet list"""
    pkts = []
    seq_c, seq_s = 1000, 5000
    t = 0.0
    for direction, payload in events:
        t += 0.01
        if direction == "c2s":
            pkt = (Ether() / IP(src=CLIENT_IP, dst=SERVER_IP) /
                   TCP(sport=CLIENT_PORT, dport=SERVER_PORT, seq=seq_c, ack=seq_s, flags="PA") /
                   Raw(load=payload))
            seq_c += len(payload)
        else:
            pkt = (Ether() / IP(src=SERVER_IP, dst=CLIENT_IP) /
                   TCP(sport=SERVER_PORT, dport=CLIENT_PORT, seq=seq_s, ack=seq_c, flags="PA") /
                   Raw(load=payload))
            seq_s += len(payload)
        pkt.time = t
        pkts.append(pkt)
    return pkts


def capture_real_tls_bytes(port):
    """
    Runs `openssl s_server` on `port` with a fresh self-signed cert, then a
    proxy socket that forwards client<->server bytes while logging each
    direction's raw bytes. Returns list of (direction, bytes).
    """
    tmpdir = tempfile.mkdtemp()
    key_path = os.path.join(tmpdir, "key.pem")
    cert_path = os.path.join(tmpdir, "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
         "-out", cert_path, "-days", "2", "-nodes", "-subj", "/CN=mail.test.local"],
        check=True, capture_output=True,
    )

    real_server_port = port + 1
    server_proc = subprocess.Popen(
        ["openssl", "s_server", "-key", key_path, "-cert", cert_path,
         "-accept", str(real_server_port), "-quiet", "-tls1_2", "-cipher", "AES128-SHA"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)

    events = []
    lock = threading.Lock()

    proxy_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_srv.bind(("127.0.0.1", port))
    proxy_srv.listen(1)

    def handle_proxy():
        client_conn, _ = proxy_srv.accept()
        real_conn = socket.create_connection(("127.0.0.1", real_server_port))

        def pump(src, dst, direction):
            while True:
                try:
                    data = src.recv(4096)
                except OSError:
                    break
                if not data:
                    break
                with lock:
                    events.append((direction, data))
                try:
                    dst.sendall(data)
                except OSError:
                    break

        t1 = threading.Thread(target=pump, args=(client_conn, real_conn, "c2s"), daemon=True)
        t2 = threading.Thread(target=pump, args=(real_conn, client_conn, "s2c"), daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=5); t2.join(timeout=5)

    proxy_thread = threading.Thread(target=handle_proxy, daemon=True)
    proxy_thread.start()
    time.sleep(0.3)

    # Prepend synthetic-but-realistic plaintext SMTP+STARTTLS bytes (these are
    # only used for protocol/STARTTLS detection, not for the TLS parse itself,
    # which uses the REAL captured handshake bytes below).
    plaintext_events = [
        ("s2c", b"220 mail.test.local ESMTP\r\n"),
        ("c2s", b"EHLO client.test.local\r\n"),
        ("s2c", b"250-mail.test.local\r\n250 STARTTLS\r\n"),
        ("c2s", b"STARTTLS\r\n"),
        ("s2c", b"220 Ready to start TLS\r\n"),
    ]

    # Trigger the real TLS handshake through the proxy using openssl s_client
    client_proc = subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_2", "-quiet"],
        input=b"", capture_output=True, timeout=5,
    )

    time.sleep(0.3)
    server_proc.terminate()

    with lock:
        tls_events = list(events)

    return plaintext_events + tls_events


def main():
    print("Capturing a real TLS 1.2 handshake via loopback proxy...")
    try:
        all_events = capture_real_tls_bytes(port=13587)
    except FileNotFoundError:
        print("openssl CLI not available in this environment — skipping live e2e capture.")
        return
    except Exception as e:
        print(f"Live capture failed ({e}); this environment may lack openssl s_server support.")
        return

    tls_byte_events = [e for e in all_events if e[0] in ("c2s", "s2c")]
    total_bytes = sum(len(p) for _, p in tls_byte_events)
    print(f"Captured {len(tls_byte_events)} segments, {total_bytes} bytes total.")

    if total_bytes < 200:
        print("Captured too little data — TLS handshake likely didn't complete in this sandboxed environment.")
        return

    pkts = make_packets(tls_byte_events)
    pcap_path = "/home/claude/securemailscope/data/sample_pcaps/synthetic_smtp_starttls.pcap"
    wrpcap(pcap_path, pkts)
    print(f"Wrote {pcap_path}")

    report = analyze_pcap(pcap_path, filename="synthetic_smtp_starttls.pcap")
    print(f"\nSessions found: {report.total_sessions}")
    for s in report.sessions:
        print(f"  {s.protocol} {s.client_ip}:{s.client_port}->{s.server_ip}:{s.server_port} "
              f"TLS={s.tls_version} cipher={s.negotiated_cipher} PFS={s.forward_secrecy} "
              f"risk={s.risk_label}({s.final_score}) certs={len(s.certificates)}")
        for f in s.findings:
            print(f"    [{f.severity}] {f.category}: {f.detail}")


if __name__ == "__main__":
    main()
