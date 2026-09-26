# 🛡️ SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

**Problem Statement ID:** 26159  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  

---

## 📌 Executive Overview
**SecureMailScope** is a passive network forensic framework designed to analyze packet captures (`.pcap` / `.pcapng`) of enterprise email traffic (**SMTP, IMAP, and POP3**). It reconstructs complete TCP streams, detects encryption transitions (STARTTLS vs. Direct TLS vs. Cleartext), audits TLS handshakes and X.509 certificate chains, and utilizes **Machine Learning (Isolation Forest)** and **NIST SP 800-52r2** compliance rules to assign an overall cryptographic posture score (A+ through F) and prioritize mitigation actions.

---

## 🚀 Key Capabilities
1. **Application-Layer Dissection**: Automatic identification of SMTP (Port 25/587), SMTPS (465), IMAP (143), IMAPS (993), POP3 (110), and POP3S (995).
2. **Encryption Transition Tracking**: Detects cleartext commands, STARTTLS upgrades, and STARTTLS stripping/downgrades.
3. **Cryptographic & TLS Audit**:
   - Dissects negotiated TLS versions (TLS 1.0, 1.1, 1.2, 1.3, SSLv2/v3).
   - Audits cipher suites (broken ciphers like RC4, 3DES, NULL, weak MACs).
   - Forward Secrecy (PFS) verification (ECDHE/DHE vs static RSA).
4. **X.509 Certificate Chain Analysis**:
   - Certificate validity and expiration checks.
   - Public key algorithm & key length evaluation (e.g., flagging weak RSA < 2048-bit).
   - Untrusted and self-signed certificate detection.
5. **AI-Assisted Anomaly Detection**:
   - Feature vector extraction for outlier TLS session discovery using `IsolationForest`.
6. **Executive & Technical Reporting**:
   - Real-time interactive Streamlit web dashboard.
   - Downloadable forensic reports in both **JSON** and **PDF** formats.

---

## 💻 Quick Start & Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Synthetic Test PCAPs (Demo Samples)
```bash
python generate_samples.py
```

### 3. Launch Interactive Security Dashboard
```bash
streamlit run app.py
```

---

## 📊 Project Architecture
```
PCAP File (.pcap) 
       │
       ▼
[ MailStreamAnalyzer (analyzer.py) ]
  ├── 1. TCP Stream Reassembly
  ├── 2. SMTP/IMAP/POP3 Protocol Classifier
  ├── 3. STARTTLS Negotiation Validator
  ├── 4. TLS Record & Handshake Dissector
  └── 5. X.509 Certificate Chain Validator
       │
       ▼
[ Posture Evaluator & AI Engine (evaluator.py) ]
  ├── NIST SP 800-52r2 & RFC 8996 Compliance Rule Engine
  ├── AI TLS Anomaly Detector (Isolation Forest)
  └── Letter Grade & Numerical Posture Scoring (0-100)
       │
       ▼
[ Web Dashboard & Report Exporter (app.py, reporter.py) ]
  ├── Interactive Streamlit SOC Dashboard
  ├── JSON SIEM Log Export
  └── Formal Forensic PDF Audit Report
```
