"""
SecureMailScope - AI & Cryptographic Posture Evaluation Engine
Applies rule-based compliance checks (NIST SP 800-52r2), Named CVE Attack Mapping,
Post-Quantum Readiness Assessment (NIST FIPS 203), and Machine Learning (Isolation Forest).
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import ciphers_db

class CryptographicEvaluator:
    def __init__(self):
        self.ml_model = None

    def evaluate_session(self, session: dict) -> dict:
        """Evaluate a single email communication stream and calculate its risk posture."""
        score = 100
        penalties = []
        recommendations = []
        named_cves = []
        severity = "Low"

        enc_mode = session.get("encryption_mode", "Plaintext")
        tls = session.get("tls_details", {})
        has_tls = tls.get("has_tls", False)

        # 1. Plaintext & STARTTLS Insecurity Checks
        if enc_mode == "Plaintext":
            score -= 60
            penalties.append(("Critical", "Plaintext Communication", "Session is completely unencrypted. Subject to eavesdropping and MITM tampering."))
            named_cves.append("CWE-319: Cleartext Transmission of Sensitive Information")
            recommendations.append("Enforce Mandatory TLS (Port 465/993/995) or enable Strict STARTTLS.")

        if session.get("plaintext_auth_leaked"):
            score -= 40
            penalties.append(("Critical", "Cleartext Credentials Exposed", "User credentials transmitted in plain text over the network."))
            named_cves.append("CWE-522: Insufficiently Protected Credentials")
            recommendations.append("Immediately rotate compromised credentials and disable cleartext AUTH mechanisms on the mail server.")

        if enc_mode == "STARTTLS Failed/Stripped":
            score -= 50
            penalties.append(("High", "STARTTLS Downgrade / Stripping Detected", "STARTTLS command was initiated but failed or downgraded."))
            named_cves.append("STRIPTLS MITM Downgrade")
            recommendations.append("Deploy MTA-STS (RFC 8461) and DANE-SMTP (RFC 7672) to prevent active STARTTLS stripping attacks.")

        # 2. TLS Version Checks
        if has_tls and tls.get("negotiated_version"):
            ver_info = tls["negotiated_version"]
            ver_name = ver_info.get("name", "")
            ver_cves = ver_info.get("version_cves", [])
            named_cves.extend(ver_cves)

            if "SSL" in ver_name or "TLS 1.0" in ver_name or "TLS 1.1" in ver_name:
                score -= 40
                penalties.append(("High", f"Obsolete TLS Protocol ({ver_name})", "Vulnerable to BEAST, POODLE, and downgrade attacks. Violates RFC 8996."))
                recommendations.append("Disable SSL 2.0/3.0 and TLS 1.0/1.1. Minimum permitted standard is TLS 1.2; recommended is TLS 1.3.")
            elif "TLS 1.2" in ver_name:
                score -= 5  # Minor deduction if TLS 1.3 is available
            elif "TLS 1.3" in ver_name:
                score += 5  # Reward modern standard

        # 3. Cipher Suite & Forward Secrecy Checks
        if has_tls and tls.get("cipher_suite"):
            cipher = tls["cipher_suite"]
            cipher_cves = cipher.get("named_cves", [])
            named_cves.extend(cipher_cves)

            if cipher.get("rating") == "Critical":
                score -= 35
                penalties.append(("Critical", f"Broken Cipher Suite ({cipher.get('name')})", cipher.get('notes', 'Known cryptographic vulnerabilities.')))
                recommendations.append("Remove deprecated ciphers (RC4, 3DES, CBC mode) from server cipher suite configuration.")
            elif cipher.get("rating") == "Warning":
                score -= 15
                penalties.append(("Medium", f"Sub-optimal Cipher ({cipher.get('name')})", cipher.get('notes', 'Weak MAC or lack of AEAD.')))
                recommendations.append("Prioritize AEAD ciphers (AES-GCM, ChaCha20-Poly1305).")

            if not cipher.get("forward_secrecy", False):
                score -= 20
                penalties.append(("High", "No Perfect Forward Secrecy (PFS)", "Static RSA key exchange allows past sessions to be decrypted if server private key is compromised."))
                recommendations.append("Configure Ephemeral Diffie-Hellman (ECDHE or DHE) key exchange algorithms.")

        # 4. X.509 Certificate Checks
        for cert in tls.get("certificates", []):
            if cert.get("is_expired"):
                score -= 30
                penalties.append(("High", "Expired X.509 Certificate", f"Certificate expired on {cert.get('valid_to')}."))
                recommendations.append("Renew server certificates and implement automated ACME (Let's Encrypt / Vault) renewal.")
            if cert.get("is_self_signed"):
                score -= 25
                penalties.append(("Medium", "Self-Signed Certificate", "Untrusted root CA makes connections vulnerable to MITM interception."))
                recommendations.append("Replace self-signed certificates with ones issued by a trusted public or corporate PKI CA.")
            for iss in cert.get("issues", []):
                if "Weak Key Size" in iss or "Insecure Signature" in iss:
                    score -= 20
                    penalties.append(("High", "Certificate Cryptographic Flaw", iss))
                    recommendations.append("Generate RSA keys >= 2048-bit (or ECC P-256) signed with SHA-256+.")

        # 5. Post-Quantum Cryptography (PQC) Readiness Assessment
        pqc_evaluation = ciphers_db.evaluate_pqc_readiness(tls, tls.get("certificates", []))

        # 6. MITRE ATT&CK Matrix Mapping
        mitre_tactics = []
        if enc_mode == "Plaintext":
            mitre_tactics.append({"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access / Discovery", "severity": "Critical"})
            mitre_tactics.append({"id": "T1565.002", "name": "Transmitted Data Manipulation", "tactic": "Impact", "severity": "High"})
        if session.get("plaintext_auth_leaked"):
            mitre_tactics.append({"id": "T1552.001", "name": "Credentials in Files / Cleartext", "tactic": "Credential Access", "severity": "Critical"})
        if enc_mode == "STARTTLS Failed/Stripped":
            mitre_tactics.append({"id": "T1557.002", "name": "Adversary-in-the-Middle: TLS Inspection/Stripping", "tactic": "Credential Access", "severity": "Critical"})
        if has_tls and tls.get("cipher_suite", {}).get("rating") == "Critical":
            mitre_tactics.append({"id": "T1600.001", "name": "Weaken Encryption: Reduce Key Space (SWEET32/RC4)", "tactic": "Defense Evasion", "severity": "High"})
        if not tls.get("forward_secrecy", True):
            mitre_tactics.append({"id": "T1600.002", "name": "Weaken Encryption: Disable PFS (Static RSA)", "tactic": "Collection", "severity": "Medium"})
        for cert in tls.get("certificates", []):
            if cert.get("is_expired") or cert.get("is_self_signed"):
                mitre_tactics.append({"id": "T1588.004", "name": "Obtain Capabilities: Invalid Digital Certificates", "tactic": "Resource Development", "severity": "Medium"})

        # Normalize score between 0 and 100
        score = max(0, min(100, score))

        if score >= 85:
            grade = "A (Secure)"
            severity = "Low"
        elif score >= 70:
            grade = "B (Good)"
            severity = "Low"
        elif score >= 50:
            grade = "C (Medium Risk)"
            severity = "Medium"
        elif score >= 30:
            grade = "D (High Risk)"
            severity = "High"
        else:
            grade = "F (Critical Vulnerability)"
            severity = "Critical"
        return {
            "posture_score": score,
            "posture_grade": grade,
            "overall_severity": severity,
            "penalties": penalties,
            "named_cves": list(set(named_cves)),
            "mitre_techniques": mitre_tactics,
            "pqc_readiness": pqc_evaluation,
            "recommendations": list(set(recommendations))
        }

    def train_and_detect_anomalies(self, sessions: list) -> list:
        """Extract feature vectors from sessions and run ML Isolation Forest for anomaly detection."""
        if not sessions:
            return sessions

        feature_matrix = []
        for s in sessions:
            tls = s.get("tls_details", {})
            
            ver_name = tls.get("negotiated_version", {}).get("name", "") if tls.get("negotiated_version") else ""
            if "TLS 1.3" in ver_name:
                ver_feat = 4
            elif "TLS 1.2" in ver_name:
                ver_feat = 3
            elif "TLS 1.1" in ver_name:
                ver_feat = 2
            elif "TLS 1.0" in ver_name:
                ver_feat = 1
            else:
                ver_feat = 0

            cipher_rate = 0
            if tls.get("cipher_suite"):
                r = tls["cipher_suite"].get("rating")
                cipher_rate = 2 if r == "Secure" else (1 if r == "Warning" else 0)

            pfs_feat = 1 if tls.get("forward_secrecy") else 0
            cert_issues = sum(len(c.get("issues", [])) for c in tls.get("certificates", []))
            auth_leak = 1 if s.get("plaintext_auth_leaked") else 0

            feature_matrix.append([ver_feat, cipher_rate, pfs_feat, cert_issues, auth_leak])

        X = np.array(feature_matrix)
        contamination = 0.2 if len(X) >= 5 else 0.1
        iso = IsolationForest(contamination=contamination, random_state=42)
        
        try:
            predictions = iso.fit_predict(X)
            scores = iso.decision_function(X)
        except Exception:
            predictions = [1] * len(X)
            scores = [0.0] * len(X)

        for idx, s in enumerate(sessions):
            is_anomaly = bool(predictions[idx] == -1)
            s["ai_anomaly_flag"] = is_anomaly
            s["ai_anomaly_confidence"] = round(float(abs(scores[idx])), 3)

        return sessions

def generate_mta_sts_policy(domain="enterprise.internal", mode="enforce", max_age=86400, mx_hosts=None):
    """Auto-generates RFC 8461 MTA-STS policy text and DNS TXT record snippet."""
    if mx_hosts is None:
        mx_hosts = [f"mail.{domain}"]
    
    mx_lines = "\n".join([f"mx: {h}" for h in mx_hosts])
    policy_body = f"""version: STSv1
mode: {mode}
{mx_lines}
max_age: {max_age}
"""
    dns_txt = f'_mta-sts.{domain}. IN TXT "v=STSv1; id={int(np.datetime64("now").astype(int))}"'
    return {"policy_file": policy_body, "dns_record": dns_txt}
