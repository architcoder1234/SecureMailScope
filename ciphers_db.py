"""
SecureMailScope - Cipher Suite, Cryptographic & Threat Database
Maps IANA TLS Cipher Suite Hex codes to cryptographic parameters,
Forward Secrecy status, NIST SP 800-52r2 compliance, Named CVE Attack Vectors,
and Post-Quantum Cryptography (PQC) Readiness.
"""

TLS_VERSIONS = {
    0x0200: "SSL 2.0 (Obsolete & Highly Insecure)",
    0x0300: "SSL 3.0 (Obsolete & Vulnerable to POODLE)",
    0x0301: "TLS 1.0 (Deprecated - RFC 8996)",
    0x0302: "TLS 1.1 (Deprecated - RFC 8996)",
    0x0303: "TLS 1.2 (Standard)",
    0x0304: "TLS 1.3 (Modern & Secure)"
}

# Cipher database: (Name, KeyExchange, Cipher, Mac, ForwardSecrecy, SecurityRating, Notes, CVE_Vulnerabilities)
CIPHER_SUITES = {
    # TLS 1.3 Ciphers (Always Forward Secret)
    0x1301: ("TLS_AES_128_GCM_SHA256", "ECDHE/DHE", "AES-128-GCM", "AEAD", True, "Secure", "Modern NIST Approved", []),
    0x1302: ("TLS_AES_256_GCM_SHA384", "ECDHE/DHE", "AES-256-GCM", "AEAD", True, "Secure", "Modern NIST Approved", []),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "ECDHE/DHE", "ChaCha20-Poly1305", "AEAD", True, "Secure", "Modern High Performance", []),
    0x1304: ("TLS_AES_128_CCM_SHA256", "ECDHE/DHE", "AES-128-CCM", "AEAD", True, "Secure", "NIST Approved", []),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", "ECDHE/DHE", "AES-128-CCM-8", "AEAD", True, "Secure", "NIST Approved", []),

    # Secure TLS 1.2 ECDHE Ciphers (PFS)
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-128-GCM", "AEAD", True, "Secure", "NIST SP 800-52r2 Compliant", []),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "AES-128-GCM", "AEAD", True, "Secure", "NIST SP 800-52r2 Compliant", []),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-256-GCM", "AEAD", True, "Secure", "NIST SP 800-52r2 Compliant", []),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "AES-256-GCM", "AEAD", True, "Secure", "NIST SP 800-52r2 Compliant", []),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", "AEAD", True, "Secure", "Secure", []),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ChaCha20-Poly1305", "AEAD", True, "Secure", "Secure", []),

    # Warning / Legacy TLS 1.2 CBC Ciphers (Vulnerable to Lucky13 / padding oracle if misconfigured)
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "AES-128-CBC", "SHA1", True, "Warning", "Uses Weak SHA1 MAC", ["LUCKY13 (CVE-2013-0169)"]),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "AES-256-CBC", "SHA1", True, "Warning", "Uses Weak SHA1 MAC", ["LUCKY13 (CVE-2013-0169)"]),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "AES-128-CBC", "SHA256", True, "Warning", "CBC Mode Vulnerable to Padding Oracles", ["LUCKY13 (CVE-2013-0169)"]),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "AES-256-CBC", "SHA384", True, "Warning", "CBC Mode Vulnerable to Padding Oracles", ["LUCKY13 (CVE-2013-0169)"]),

    # Non-PFS Static RSA Key Exchange (Critical: Vulnerable to retrospective decryption)
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "AES-128-CBC", "SHA1", False, "Critical", "No Forward Secrecy, Weak SHA1", ["ROBOT Attack (CVE-2017-13099)", "BEAST (CVE-2011-3389)"]),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "AES-256-CBC", "SHA1", False, "Critical", "No Forward Secrecy, Weak SHA1", ["ROBOT Attack (CVE-2017-13099)", "BEAST (CVE-2011-3389)"]),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", "AES-128-GCM", "AEAD", False, "Warning", "No Forward Secrecy", ["ROBOT Attack (CVE-2017-13099)"]),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", "AES-256-GCM", "AEAD", False, "Warning", "No Forward Secrecy", ["ROBOT Attack (CVE-2017-13099)"]),

    # Insecure / Broken Legacy Ciphers (Critical)
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RC4-128", "MD5", False, "Critical", "Broken RC4 & MD5", ["Bar Mitzvah (CVE-2015-2808)", "NOMORE Attack", "ROBOT Attack"]),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RC4-128", "SHA1", False, "Critical", "Broken RC4 Stream Cipher", ["Bar Mitzvah (CVE-2015-2808)", "NOMORE Attack"]),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "3DES", "SHA1", False, "Critical", "Vulnerable to Sweet32 (64-bit block)", ["Sweet32 (CVE-2016-2183)"]),
    0x0001: ("TLS_RSA_WITH_NULL_MD5", "RSA", "NULL", "MD5", False, "Critical", "Cleartext / No Encryption", ["Cleartext Interception"]),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", "RSA", "NULL", "SHA1", False, "Critical", "Cleartext / No Encryption", ["Cleartext Interception"]),
    0x0003: ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA-Export", "RC4-40", "MD5", False, "Critical", "Export Grade Weak Encryption", ["FREAK (CVE-2015-0204)", "LOGJAM (CVE-2015-4000)"]),
}

def lookup_cipher(cipher_id: int):
    """Retrieve cipher suite metadata and attack vectors."""
    if cipher_id in CIPHER_SUITES:
        name, kx, cipher, mac, pfs, rating, notes, cves = CIPHER_SUITES[cipher_id]
        return {
            "id": hex(cipher_id),
            "name": name,
            "key_exchange": kx,
            "cipher": cipher,
            "mac": mac,
            "forward_secrecy": pfs,
            "rating": rating,
            "notes": notes,
            "named_cves": cves
        }
    return {
        "id": hex(cipher_id),
        "name": f"Unknown Cipher ({hex(cipher_id)})",
        "key_exchange": "Unknown",
        "cipher": "Unknown",
        "mac": "Unknown",
        "forward_secrecy": False,
        "rating": "Warning",
        "notes": "Unrecognized or proprietary cipher suite",
        "named_cves": []
    }

def lookup_tls_version(version_code: int):
    """Resolve TLS version code to string, status, and historical exploits."""
    name = TLS_VERSIONS.get(version_code, f"Unknown TLS ({hex(version_code)})")
    cves = []
    if version_code == 0x0200:
        status = "Critical"
        cves = ["DROWN Attack (CVE-2016-0800)", "Export Ciphers"]
    elif version_code == 0x0300:
        status = "Critical"
        cves = ["POODLE (CVE-2014-3566)"]
    elif version_code == 0x0301:
        status = "Critical"
        cves = ["BEAST (CVE-2011-3389)", "RFC 8996 Deprecated"]
    elif version_code == 0x0302:
        status = "Critical"
        cves = ["RFC 8996 Deprecated"]
    elif version_code == 0x0303:
        status = "Good"
    elif version_code == 0x0304:
        status = "Secure"
    else:
        status = "Warning"
    return {"name": name, "raw_code": hex(version_code), "status": status, "version_cves": cves}

def evaluate_pqc_readiness(tls_details: dict, cert_details: list):
    """
    Evaluates Post-Quantum Cryptography (PQC) Readiness according to NIST FIPS 203/204.
    Identifies if session uses Classical (Shor's vulnerable) or Hybrid Quantum-Resistant algorithms.
    """
    pqc_status = {
        "is_pqc_ready": False,
        "threat_level": "High (Harvest Now, Decrypt Later)",
        "details": [],
        "quantum_vulnerable_algorithms": []
    }

    if not tls_details.get("has_tls"):
        pqc_status["threat_level"] = "Critical (Unencrypted Plaintext)"
        pqc_status["details"].append("Plaintext transmission provides zero cryptographic protection against any adversary.")
        return pqc_status

    kx = tls_details.get("key_exchange", "")
    if "Kyber" in kx or "ML-KEM" in kx or "FrodoKEM" in kx:
        pqc_status["is_pqc_ready"] = True
        pqc_status["threat_level"] = "Secure (Quantum-Resistant KEM)"
        pqc_status["details"].append("Session negotiates a Post-Quantum KEM (e.g., ML-KEM / Kyber-768 hybrid).")
    else:
        pqc_status["quantum_vulnerable_algorithms"].append(f"Key Exchange: {kx} (Vulnerable to Shor's Algorithm on Q-Day)")
        pqc_status["details"].append("Session relies on classical Discrete Logarithm or Elliptic Curve Diffie-Hellman vulnerable to quantum cryptanalysis.")

    for cert in cert_details:
        key_algo = cert.get("key_algorithm", "")
        if "RSA" in key_algo or "EC" in key_algo:
            pqc_status["quantum_vulnerable_algorithms"].append(f"Certificate Key: {key_algo} (Classical Public Key)")
            pqc_status["details"].append(f"Digital signature authentication uses classical {key_algo}; transition to ML-DSA (Dilithium) / SLH-DSA recommended.")

    return pqc_status
