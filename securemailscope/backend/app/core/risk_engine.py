"""
Combines rule-based cryptographic risk scoring with an ML anomaly layer.

Rule-based scoring gives an explainable baseline (required for SOC/forensic
use — analysts need to know *why* something scored high). The ML layer
(IsolationForest) flags sessions whose feature vectors are statistical
outliers relative to the rest of the capture, catching anomalies that fixed
rules might miss (e.g. unusual cipher/version combinations).

NOTE: IsolationForest here is unsupervised and needs no labeled data, which
fits the "synthetic, participant-generated" dataset situation. If you later
collect labeled good/bad sessions, swap in a RandomForestClassifier for
supervised risk classification (see train_supervised() below).
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
import numpy as np

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
except ImportError:
    IsolationForest = None
    RandomForestClassifier = None

from .tls_handshake import HandshakeInfo, WEAK_CIPHER_MARKERS, TLS_VERSION_NAMES
from .cert_analyzer import CertFinding

DEPRECATED_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}


@dataclass
class Finding:
    severity: str   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    category: str
    detail: str


@dataclass
class SessionRisk:
    session_id: str
    protocol: str
    findings: List[Finding] = field(default_factory=list)
    base_score: int = 0          # 0-100, higher = worse, from rules
    anomaly_score: float = 0.0   # from IsolationForest, higher = more anomalous
    final_score: int = 0
    risk_label: str = "LOW"


def _score_from_findings(findings: List[Finding]) -> int:
    weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 0}
    score = sum(weights.get(f.severity, 0) for f in findings)
    return min(score, 100)


def evaluate_session_rules(session_id: str, protocol: str, starttls_seen: bool,
                            handshake: HandshakeInfo, certs: List[CertFinding]) -> SessionRisk:
    findings: List[Finding] = []

    if not starttls_seen and handshake.server_hello_version is None:
        findings.append(Finding("CRITICAL", "Encryption", "Session appears fully plaintext — no STARTTLS or TLS observed."))

    version = handshake.server_hello_version
    if version in DEPRECATED_VERSIONS:
        findings.append(Finding("HIGH", "Protocol Version", f"Deprecated TLS version negotiated: {version}."))
    elif version is None and (starttls_seen or protocol.endswith("S")):
        findings.append(Finding("MEDIUM", "Protocol Version", "TLS was expected but version could not be determined (possible parsing gap or truncated capture)."))

    cipher = handshake.negotiated_cipher or ""
    if any(marker in cipher.upper() for marker in WEAK_CIPHER_MARKERS):
        findings.append(Finding("CRITICAL", "Cipher Suite", f"Weak/deprecated cipher negotiated: {cipher}."))

    if handshake.negotiated_cipher and not handshake.forward_secrecy:
        findings.append(Finding("MEDIUM", "Forward Secrecy", f"Negotiated cipher lacks forward secrecy: {cipher}."))

    for cert in certs:
        if cert.is_expired:
            findings.append(Finding("HIGH", "Certificate", f"Certificate expired ({cert.not_after}): {cert.subject}."))
        elif 0 <= cert.days_until_expiry <= 14:
            findings.append(Finding("MEDIUM", "Certificate", f"Certificate expiring soon ({cert.days_until_expiry}d): {cert.subject}."))
        if cert.is_self_signed:
            findings.append(Finding("MEDIUM", "Certificate", f"Self-signed certificate: {cert.subject}."))
        if not cert.key_size_adequate:
            findings.append(Finding("HIGH", "Certificate", f"Weak public key ({cert.public_key_type} {cert.public_key_size} bits): {cert.subject}."))
        if cert.weak_signature:
            findings.append(Finding("CRITICAL", "Certificate", f"Weak signature algorithm ({cert.signature_algorithm}): {cert.subject}."))

    if not findings:
        findings.append(Finding("INFO", "Overall", "No cryptographic weaknesses detected against current ruleset."))

    base_score = _score_from_findings(findings)
    risk = SessionRisk(session_id=session_id, protocol=protocol, findings=findings, base_score=base_score)
    return risk


def _label_from_score(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def build_feature_vector(handshake: HandshakeInfo, certs: List[CertFinding]) -> List[float]:
    version_rank = {"SSL 3.0": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
    v = version_rank.get(handshake.server_hello_version, -1)
    weak_cipher = 1.0 if handshake.negotiated_cipher and any(
        m in handshake.negotiated_cipher.upper() for m in WEAK_CIPHER_MARKERS) else 0.0
    pfs = 1.0 if handshake.forward_secrecy else 0.0
    min_key_size = min([c.public_key_size for c in certs], default=0)
    any_expired = 1.0 if any(c.is_expired for c in certs) else 0.0
    any_self_signed = 1.0 if any(c.is_self_signed for c in certs) else 0.0
    any_weak_sig = 1.0 if any(c.weak_signature for c in certs) else 0.0
    return [float(v), weak_cipher, pfs, float(min_key_size), any_expired, any_self_signed, any_weak_sig]


def apply_anomaly_detection(sessions: List[SessionRisk], feature_vectors: List[List[float]]) -> None:
    """Mutates sessions in place, setting anomaly_score and final_score/risk_label."""
    if not sessions:
        return
    if IsolationForest is not None and len(sessions) >= 4:
        X = np.array(feature_vectors)
        clf = IsolationForest(contamination="auto", random_state=42)
        clf.fit(X)
        raw_scores = -clf.score_samples(X)  # higher = more anomalous
        norm = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)
    else:
        norm = np.zeros(len(sessions))

    for session, a_score in zip(sessions, norm):
        session.anomaly_score = float(a_score)
        combined = session.base_score * 0.75 + (a_score * 100) * 0.25
        session.final_score = int(min(combined, 100))
        session.risk_label = _label_from_score(session.final_score)


def train_supervised(feature_vectors: List[List[float]], labels: List[int]):
    """
    Optional: once you have labeled sessions (0=benign, 1=risky), train a
    RandomForestClassifier instead of relying purely on rules + anomaly score.
    Not wired into the default pipeline — call this manually with your own
    labeled dataset once you've generated enough synthetic traffic.
    """
    if RandomForestClassifier is None:
        raise RuntimeError("scikit-learn not installed")
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(np.array(feature_vectors), np.array(labels))
    return clf
