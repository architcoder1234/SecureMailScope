"""
Identifies which application-layer email protocol a TCP stream carries,
and locates the byte offset at which STARTTLS/STLS upgrades the session
to TLS (or whether the session was TLS from the first byte, e.g. port 465/993/995).
"""
from dataclasses import dataclass
from typing import Optional
from ..utils.tcp_reassembly import TCPStream

IMPLICIT_TLS_PORTS = {465: "SMTPS", 993: "IMAPS", 995: "POP3S"}
PLAINTEXT_PORTS = {25: "SMTP", 587: "SMTP", 143: "IMAP", 110: "POP3"}


@dataclass
class ProtocolInfo:
    protocol: str                 # SMTP / IMAP / POP3
    is_implicit_tls: bool         # True if TLS from byte 0 (SMTPS/IMAPS/POP3S)
    starttls_seen: bool           # True if STARTTLS/STLS command observed
    starttls_offset_c2s: Optional[int] = None  # byte offset in client stream where TLS begins
    starttls_offset_s2c: Optional[int] = None


def detect_protocol(stream: TCPStream) -> Optional[ProtocolInfo]:
    _, _, server_ip, server_port = stream.key

    if server_port in IMPLICIT_TLS_PORTS:
        return ProtocolInfo(
            protocol=IMPLICIT_TLS_PORTS[server_port].replace("S", ""),
            is_implicit_tls=True,
            starttls_seen=False,
        )

    if server_port not in PLAINTEXT_PORTS:
        # Not a recognized email port; skip (could extend with banner sniffing)
        return None

    protocol = PLAINTEXT_PORTS[server_port]
    starttls_seen = False
    c2s_offset = None
    s2c_offset = None

    client_running = b""
    server_running = b""
    starttls_cmd = {
        "SMTP": b"STARTTLS",
        "IMAP": b"STARTTLS",
        "POP3": b"STLS",
    }[protocol]
    ok_response_prefix = {
        "SMTP": b"220",   # 220 ready to start TLS
        "IMAP": b"a",     # tagged OK, protocol-specific; loosely matched below
        "POP3": b"+OK",
    }[protocol]

    for ts, direction, payload in stream.full_ordered_payloads():
        if direction == "c2s":
            client_running += payload
            if not starttls_seen and starttls_cmd in payload.upper():
                starttls_seen = True
                # mark offset AFTER this command in the client stream
                c2s_offset = len(client_running)
        else:
            server_running += payload
            if starttls_seen and s2c_offset is None:
                # look for the server's positive acknowledgement, then TLS begins right after
                upper = payload.upper()
                if protocol == "IMAP":
                    if b"OK" in upper:
                        s2c_offset = len(server_running)
                elif ok_response_prefix in payload:
                    s2c_offset = len(server_running)

    return ProtocolInfo(
        protocol=protocol,
        is_implicit_tls=False,
        starttls_seen=starttls_seen,
        starttls_offset_c2s=c2s_offset,
        starttls_offset_s2c=s2c_offset,
    )
