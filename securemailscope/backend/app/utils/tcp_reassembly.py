"""
Reassembles raw packets from a PCAP into ordered, bidirectional TCP streams.
Each stream is keyed by a normalized 4-tuple (so both directions map to one key)
and holds an ordered list of (timestamp, direction, payload_bytes).
"""
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Tuple
from scapy.all import rdpcap, TCP, IP


@dataclass
class TCPStream:
    key: Tuple[str, int, str, int]  # (client_ip, client_port, server_ip, server_port)
    packets: List[Tuple[float, str, bytes]] = field(default_factory=list)  # (ts, direction, payload)

    def client_bytes(self) -> bytes:
        return b"".join(p for _, d, p in self.packets if d == "c2s")

    def server_bytes(self) -> bytes:
        return b"".join(p for _, d, p in self.packets if d == "s2c")

    def full_ordered_payloads(self):
        """Payloads in wall-clock order, tagged by direction."""
        return sorted(self.packets, key=lambda x: x[0])


def _normalize_key(ip_a, port_a, ip_b, port_b):
    """
    Use the lower port as the 'server' side heuristically (works for
    well-known SMTP/IMAP/POP3 ports); falls back to first-seen order.
    """
    well_known = {25, 587, 465, 143, 993, 110, 995}
    if port_b in well_known and port_a not in well_known:
        return (ip_a, port_a, ip_b, port_b)
    if port_a in well_known and port_b not in well_known:
        return (ip_b, port_b, ip_a, port_a)
    # fallback: lower port = server
    if port_a <= port_b:
        return (ip_b, port_b, ip_a, port_a)
    return (ip_a, port_a, ip_b, port_b)


def reassemble_streams(pcap_path: str) -> List[TCPStream]:
    packets = rdpcap(pcap_path)
    streams = {}

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            continue

        key = _normalize_key(ip.src, tcp.sport, ip.dst, tcp.dport)
        client_ip, client_port, server_ip, server_port = key

        direction = "c2s" if (ip.src == client_ip and tcp.sport == client_port) else "s2c"

        if key not in streams:
            streams[key] = TCPStream(key=key)
        streams[key].packets.append((float(pkt.time), direction, payload))

    # sort each stream's packets by time so reassembly is in order
    for s in streams.values():
        s.packets.sort(key=lambda x: x[0])

    return list(streams.values())
