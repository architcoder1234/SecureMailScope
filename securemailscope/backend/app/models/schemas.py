from typing import List, Optional
from pydantic import BaseModel


class FindingModel(BaseModel):
    severity: str
    category: str
    detail: str


class CertModel(BaseModel):
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


class SessionReport(BaseModel):
    session_id: str
    protocol: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    starttls_seen: bool
    tls_version: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    forward_secrecy: bool = False
    certificates: List[CertModel] = []
    findings: List[FindingModel] = []
    base_score: int
    anomaly_score: float
    final_score: int
    risk_label: str


class AnalysisReport(BaseModel):
    pcap_filename: str
    total_sessions: int
    sessions: List[SessionReport]
    summary: dict
