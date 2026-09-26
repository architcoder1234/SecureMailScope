"""
Passive TLS handshake parser. Works directly on the raw bytes captured
after a STARTTLS upgrade or from the start of an implicit-TLS session.

Parses only the plaintext parts of the handshake (record layer + ClientHello/
ServerHello/Certificate). No decryption is attempted or possible.

LIMITATION: for TLS 1.3, the Certificate message is encrypted and will not
be visible here; only the negotiated version (via supported_versions
extension) and cipher suite from ServerHello are recoverable.
"""
import struct
from dataclasses import dataclass, field
from typing import List, Optional

TLS_VERSION_NAMES = {
    (3, 0): "SSL 3.0",
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}

CONTENT_TYPE_HANDSHAKE = 0x16
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0B

# Minimal cipher suite name table for common/legacy suites relevant to risk scoring.
# Extend as needed; unknown suites are reported by hex code.
CIPHER_SUITE_NAMES = {
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",       # TLS 1.3
    0x1302: "TLS_AES_256_GCM_SHA384",       # TLS 1.3
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", # TLS 1.3
}

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "NULL", "EXPORT", "MD5")


@dataclass
class HandshakeInfo:
    client_hello_version: Optional[str] = None
    client_offered_ciphers: List[str] = field(default_factory=list)
    server_hello_version: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    forward_secrecy: bool = False
    raw_certificate_ders: List[bytes] = field(default_factory=list)
    tls13_detected: bool = False


def _iter_tls_records(data: bytes):
    """Yield (content_type, version_tuple, record_payload) for each TLS record found."""
    i = 0
    n = len(data)
    while i + 5 <= n:
        content_type = data[i]
        ver_major, ver_minor = data[i + 1], data[i + 2]
        length = struct.unpack(">H", data[i + 3:i + 5])[0]
        if i + 5 + length > n or length == 0:
            break
        payload = data[i + 5:i + 5 + length]
        yield content_type, (ver_major, ver_minor), payload
        i += 5 + length


def _iter_handshake_messages(record_payload: bytes):
    i = 0
    n = len(record_payload)
    while i + 4 <= n:
        msg_type = record_payload[i]
        msg_len = int.from_bytes(record_payload[i + 1:i + 4], "big")
        if i + 4 + msg_len > n:
            break
        body = record_payload[i + 4:i + 4 + msg_len]
        yield msg_type, body
        i += 4 + msg_len


def _parse_client_hello(body: bytes, info: HandshakeInfo):
    if len(body) < 34:
        return
    ver = (body[0], body[1])
    info.client_hello_version = TLS_VERSION_NAMES.get(ver, f"0x{ver[0]:02x}{ver[1]:02x}")
    pos = 2 + 32  # version + random
    if pos >= len(body):
        return
    session_id_len = body[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(body):
        return
    cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    cipher_bytes = body[pos:pos + cs_len]
    for j in range(0, len(cipher_bytes) - 1, 2):
        code = struct.unpack(">H", cipher_bytes[j:j + 2])[0]
        info.client_offered_ciphers.append(CIPHER_SUITE_NAMES.get(code, f"0x{code:04x}"))


def _parse_server_hello(body: bytes, info: HandshakeInfo):
    if len(body) < 35:
        return
    ver = (body[0], body[1])
    info.server_hello_version = TLS_VERSION_NAMES.get(ver, f"0x{ver[0]:02x}{ver[1]:02x}")
    pos = 2 + 32
    session_id_len = body[pos]
    pos += 1 + session_id_len
    if pos + 3 > len(body):
        return
    cipher_code = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2 + 1  # cipher suite + compression method
    cipher_name = CIPHER_SUITE_NAMES.get(cipher_code, f"0x{cipher_code:04x}")
    info.negotiated_cipher = cipher_name
    info.forward_secrecy = "ECDHE" in cipher_name or "DHE" in cipher_name or cipher_name.startswith("TLS_AES") or cipher_name.startswith("TLS_CHACHA20")

    # Check extensions for supported_versions (0x002b) indicating TLS 1.3
    if pos + 2 <= len(body):
        ext_total_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        ext_end = min(pos + ext_total_len, len(body))
        while pos + 4 <= ext_end:
            ext_type = struct.unpack(">H", body[pos:pos + 2])[0]
            ext_len = struct.unpack(">H", body[pos + 2:pos + 4])[0]
            ext_data = body[pos + 4: pos + 4 + ext_len]
            if ext_type == 0x002B and len(ext_data) >= 2:
                sv = (ext_data[0], ext_data[1])
                if sv == (3, 4):
                    info.tls13_detected = True
                    info.server_hello_version = "TLS 1.3"
            pos += 4 + ext_len


def _parse_certificate_message(body: bytes, info: HandshakeInfo):
    # TLS 1.2 and earlier structure: 3-byte total length, then list of (3-byte len + DER cert)
    if len(body) < 3:
        return
    pos = 3  # skip total certificate_list length
    n = len(body)
    while pos + 3 <= n:
        cert_len = int.from_bytes(body[pos:pos + 3], "big")
        pos += 3
        if pos + cert_len > n:
            break
        der = body[pos:pos + cert_len]
        info.raw_certificate_ders.append(der)
        pos += cert_len


def parse_handshake(raw_bytes: bytes) -> HandshakeInfo:
    """
    raw_bytes should be the interleaved-but-time-ordered bytes of the stream
    starting from the first byte after STARTTLS ack (or from byte 0 for
    implicit TLS). Caller is responsible for slicing client/server streams
    separately and calling this once per direction, then merging results.
    """
    info = HandshakeInfo()
    for content_type, version, payload in _iter_tls_records(raw_bytes):
        if content_type != CONTENT_TYPE_HANDSHAKE:
            continue
        for msg_type, msg_body in _iter_handshake_messages(payload):
            if msg_type == HS_CLIENT_HELLO:
                _parse_client_hello(msg_body, info)
            elif msg_type == HS_SERVER_HELLO:
                _parse_server_hello(msg_body, info)
            elif msg_type == HS_CERTIFICATE:
                _parse_certificate_message(msg_body, info)
    return info


def merge_handshake_info(client_info: HandshakeInfo, server_info: HandshakeInfo) -> HandshakeInfo:
    """Combine client-side (ClientHello) and server-side (ServerHello+Certificate) parses."""
    merged = HandshakeInfo(
        client_hello_version=client_info.client_hello_version,
        client_offered_ciphers=client_info.client_offered_ciphers,
        server_hello_version=server_info.server_hello_version,
        negotiated_cipher=server_info.negotiated_cipher,
        forward_secrecy=server_info.forward_secrecy,
        raw_certificate_ders=server_info.raw_certificate_ders,
        tls13_detected=server_info.tls13_detected,
    )
    return merged
