"""
Parses X.509 certificates extracted from the TLS Certificate handshake
message and evaluates them for expiry, key strength, and signature algorithm.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import SignatureAlgorithmOID

WEAK_SIGNATURE_OIDS = {
    SignatureAlgorithmOID.RSA_WITH_MD5: "MD5",
    SignatureAlgorithmOID.RSA_WITH_SHA1: "SHA-1",
    SignatureAlgorithmOID.ECDSA_WITH_SHA1: "SHA-1",
    SignatureAlgorithmOID.DSA_WITH_SHA1: "SHA-1",
}

MIN_RSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 224


@dataclass
class CertFinding:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    is_expired: bool
    is_self_signed: bool
    public_key_type: str
    public_key_size: int
    key_size_adequate: bool
    signature_algorithm: str
    weak_signature: bool
    days_until_expiry: int


def analyze_certificates(der_list: List[bytes]) -> List[CertFinding]:
    findings = []
    now = datetime.now(timezone.utc)

    for der in der_list:
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception:
            continue

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = now > not_after
        is_self_signed = subject == issuer

        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
            key_adequate = key_size >= MIN_RSA_KEY_SIZE
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = "EC"
            key_size = pub_key.curve.key_size
            key_adequate = key_size >= MIN_EC_KEY_SIZE
        else:
            key_type = type(pub_key).__name__
            key_size = 0
            key_adequate = False

        sig_oid = cert.signature_algorithm_oid
        weak_sig = sig_oid in WEAK_SIGNATURE_OIDS
        sig_name = WEAK_SIGNATURE_OIDS.get(sig_oid, cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown")

        findings.append(CertFinding(
            subject=subject,
            issuer=issuer,
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            public_key_type=key_type,
            public_key_size=key_size,
            key_size_adequate=key_adequate,
            signature_algorithm=sig_name,
            weak_signature=weak_sig,
            days_until_expiry=(not_after - now).days,
        ))

    return findings
