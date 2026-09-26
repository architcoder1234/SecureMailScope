# 🛡️ SecureMailScope: Technical Architecture & 5-Slide Presentation Deck

---

## 🏛️ 2-Page Architecture Document

### 1. Executive Summary
**SecureMailScope** is an AI-assisted passive network forensic framework purpose-built for the National Technical Research Organisation (NTRO). It performs deep cryptographic posture evaluation across enterprise email traffic (SMTP, IMAP, and POP3) captured in PCAP format. It addresses the forensic gap between passive packet capture and automated cryptographic posture assessment.

### 2. High-Level Architecture Diagram
```text
┌────────────────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER                                 │
│  - Raw PCAP / PCAPNG File Upload (Web UI / CLI / API)                  │
│  - Offline & Air-Gapped Capable Packet Replay                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              TCP & PROTOCOL DISSECTION LAYER (analyzer.py)             │
│  - 4-Tuple Stream Reassembly: (SrcIP, SrcPort, DstIP, DstPort)        │
│  - Protocol Classification: SMTP (25/587), SMTPS (465),               │
│    IMAP (143), IMAPS (993), POP3 (110), POP3S (995)                   │
│  - State Machine: Plaintext -> STARTTLS Command -> TLS Handshake       │
│  - Cleartext Credential Leakage Detector (AUTH LOGIN / AUTH PLAIN)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│           CRYPTOGRAPHIC & CERTIFICATE ENGINE (ciphers_db.py)           │
│  - TLS Record Dissection: Record Type 0x16 (ClientHello, ServerHello)  │
│  - Version Resolver: SSLv2/v3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3     │
│  - Cipher Suite Evaluation: NIST SP 800-52r2, AEAD, Forward Secrecy    │
│  - X.509 Extraction: Subject, Issuer, RSA/ECC Key Length, Validity,   │
│    Signature Hash (MD5/SHA1/SHA256), Self-Signed Root Validation       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│          AI RISK & ANOMALY EVALUATION ENGINE (evaluator.py)            │
│  - Numerical Posture Scoring (0–100 Scale & Letter Grade A+ to F)      │
│  - Unsupervised Machine Learning: IsolationForest Outlier Detection    │
│  - Threat Prioritization & Actionable Remediation Generation          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                PRESENTATION & EXPORT LAYER (app.py, reporter.py)       │
│  - SOC-Ready Interactive Streamlit Visual Dashboard                    │
│  - Machine-Readable JSON Export (for SIEM & OpenSearch integration)    │
│  - Formal Executive PDF Audit Report Generation                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 3. Key Differentiators
1. **Zero Impact Passive Analysis**: No active probing or traffic modification; runs entirely on stored or mirrored PCAPs.
2. **Standardized Cryptographic Taxonomy**: Compliant with NIST SP 800-52 Rev 2, RFC 8996 (Deprecating TLS 1.0/1.1), RFC 8461 (MTA-STS), and RFC 7672 (DANE).
3. **Multi-Vector Threat Detection**: Catches cleartext credentials, broken ciphers (RC4, 3DES), absence of Perfect Forward Secrecy (PFS), expired certificates, and STARTTLS stripping.

---

## 📽️ 5-Slide Technical Presentation Deck (Slide-by-Slide Content)

### Slide 1: Title & Problem Context
* **Title:** SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications
* **Team:** [Your Team Name / Code]
* **Problem Statement ID:** 26159 (NTRO)
* **The Problem:** 
  * Email remains the primary vector for enterprise communication and cyber-attacks.
  * Millions of email servers still suffer from obsolete TLS versions (1.0/1.1), broken ciphers (RC4/3DES), self-signed/expired certificates, and vulnerable STARTTLS implementations.
  * Traditional packet analyzers (Wireshark/tcpdump) only decode packets—they **do not automatically audit cryptographic posture or assign actionable risk scores**.

---

### Slide 2: Proposed Solution & Core Features
* **What SecureMailScope Delivers:**
  * **Automatic Stream Reconstruction:** Reconstructs TCP streams for SMTP, IMAP, and POP3.
  * **Encryption Transition Tracker:** Accurately pinpoints plaintext-to-TLS upgrades and STARTTLS downgrade/stripping attacks.
  * **Deep Cryptographic Auditing:** Evaluates negotiated TLS versions, cipher suites, Forward Secrecy (PFS), and X.509 certificate chains.
  * **AI-Assisted Anomaly Detection:** Applies Isolation Forest ML models to flag suspicious/outlier TLS sessions.
  * **Automated Remediation:** Generates prioritized checklists and exportable PDF/JSON audit reports for SOC teams.

---

### Slide 3: Technical Architecture & Methodology
* **Workflow:**
  1. **Ingest:** Reads `.pcap` / `.pcapng` passive network captures.
  2. **Dissect:** Reassembles TCP segments and parses TLS handshake records (ClientHello, ServerHello, Certificate).
  3. **Assess:** Matches ciphers against NIST SP 800-52r2 database and validates X.509 validity dates, signature algorithms, and key lengths.
  4. **Score & Classify:** AI engine calculates a 0–100 posture score and categorizes risks (Critical, High, Medium, Low).
  5. **Report:** Real-time SOC dashboard + one-click PDF/JSON export.

---

### Slide 4: Prototype Results & Forensic Capabilities
* **Tested Scenarios:**
  * **Plaintext SMTP (Port 25):** Detected cleartext `AUTH LOGIN` credential leak $\to$ **Score: 0/100 [Grade F]**
  * **Deprecated TLS 1.0 + RC4 (Port 587):** Flagged RFC 8996 violation & broken stream cipher $\to$ **Score: 5/100 [Grade F]**
  * **IMAPS with Certificate Flaws (Port 993):** Flagged expired certificate & untrusted root $\to$ **Score: 60/100 [Grade C]**
  * **Hardened SMTPS (Port 465):** Modern TLS 1.3 with AES-256-GCM and ECDHE Forward Secrecy $\to$ **Score: 100/100 [Grade A+]**

---

### Slide 5: Impact, Compliance & Future Roadmap
* **Operational Impact for SOC & NTRO:**
  * Enables zero-overhead continuous passive monitoring of mail gateways.
  * Eliminates hours of manual packet analysis for digital forensics teams.
* **Compliance Ready:** NIST SP 800-52r2, RFC 8461 (MTA-STS), RFC 7672 (DANE).
* **Future Roadmap:**
  * Live wire sniffing via DPDK/AF_PACKET for 10Gbps+ carrier-grade inspection.
  * Post-Quantum Cryptography (PQC) readiness scoring (Kyber/Dilithium transition tracking).
