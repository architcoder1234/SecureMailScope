"""
Orchestrates the full analysis: PCAP -> streams -> protocol/STARTTLS detection
-> TLS handshake parsing -> certificate analysis -> risk scoring -> report.
"""
from typing import List
from ..utils.tcp_reassembly import reassemble_streams, TCPStream
from .protocol_detector import detect_protocol, ProtocolInfo
from .tls_handshake import parse_handshake, merge_handshake_info, HandshakeInfo
from .cert_analyzer import analyze_certificates
from .risk_engine import evaluate_session_rules, build_feature_vector, apply_anomaly_detection, SessionRisk
from ..models.schemas import SessionReport, CertModel, FindingModel, AnalysisReport


def _extract_tls_bytes(stream: TCPStream, proto_info: ProtocolInfo):
    if proto_info.is_implicit_tls:
        return stream.client_bytes(), stream.server_bytes()

    c2s = stream.client_bytes()
    s2c = stream.server_bytes()
    client_tls = c2s[proto_info.starttls_offset_c2s:] if proto_info.starttls_offset_c2s else b""
    server_tls = s2c[proto_info.starttls_offset_s2c:] if proto_info.starttls_offset_s2c else b""
    return client_tls, server_tls


def analyze_pcap(pcap_path: str, filename: str = "capture.pcap") -> AnalysisReport:
    streams = reassemble_streams(pcap_path)

    session_risks: List[SessionRisk] = []
    feature_vectors = []
    session_meta = []  # parallel list holding data needed to build SessionReport later

    for idx, stream in enumerate(streams):
        proto_info = detect_protocol(stream)
        if proto_info is None:
            continue  # not an email protocol stream

        client_ip, client_port, server_ip, server_port = stream.key
        session_id = f"sess-{idx}-{client_ip}:{client_port}->{server_ip}:{server_port}"

        handshake = HandshakeInfo()
        certs = []

        if proto_info.is_implicit_tls or proto_info.starttls_seen:
            client_tls_bytes, server_tls_bytes = _extract_tls_bytes(stream, proto_info)
            client_hs = parse_handshake(client_tls_bytes)
            server_hs = parse_handshake(server_tls_bytes)
            handshake = merge_handshake_info(client_hs, server_hs)
            certs = analyze_certificates(handshake.raw_certificate_ders)

        risk = evaluate_session_rules(
            session_id=session_id,
            protocol=proto_info.protocol,
            starttls_seen=proto_info.starttls_seen or proto_info.is_implicit_tls,
            handshake=handshake,
            certs=certs,
        )
        session_risks.append(risk)
        feature_vectors.append(build_feature_vector(handshake, certs))
        session_meta.append({
            "client_ip": client_ip, "client_port": client_port,
            "server_ip": server_ip, "server_port": server_port,
            "proto_info": proto_info, "handshake": handshake, "certs": certs,
        })

    apply_anomaly_detection(session_risks, feature_vectors)

    session_reports = []
    for risk, meta in zip(session_risks, session_meta):
        session_reports.append(SessionReport(
            session_id=risk.session_id,
            protocol=risk.protocol,
            client_ip=meta["client_ip"], client_port=meta["client_port"],
            server_ip=meta["server_ip"], server_port=meta["server_port"],
            starttls_seen=meta["proto_info"].starttls_seen or meta["proto_info"].is_implicit_tls,
            tls_version=meta["handshake"].server_hello_version,
            negotiated_cipher=meta["handshake"].negotiated_cipher,
            forward_secrecy=meta["handshake"].forward_secrecy,
            certificates=[CertModel(**c.__dict__) for c in meta["certs"]],
            findings=[FindingModel(**f.__dict__) for f in risk.findings],
            base_score=risk.base_score,
            anomaly_score=risk.anomaly_score,
            final_score=risk.final_score,
            risk_label=risk.risk_label,
        ))

    summary = {
        "critical": sum(1 for s in session_reports if s.risk_label == "CRITICAL"),
        "high": sum(1 for s in session_reports if s.risk_label == "HIGH"),
        "medium": sum(1 for s in session_reports if s.risk_label == "MEDIUM"),
        "low": sum(1 for s in session_reports if s.risk_label == "LOW"),
        "protocols_seen": sorted(set(s.protocol for s in session_reports)),
    }

    return AnalysisReport(
        pcap_filename=filename,
        total_sessions=len(session_reports),
        sessions=session_reports,
        summary=summary,
    )
