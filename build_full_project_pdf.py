"""
SecureMailScope - Complete Project Documentation PDF Generator
Generates a comprehensive, publication-grade PDF containing every detail,
architecture, code breakdown, test results, and presentation guide for the team.
"""

import os
import datetime
from fpdf import FPDF

class ProjectDocumentationPDF(FPDF):
    def header(self):
        # Header banner
        self.set_fill_color(15, 23, 42) # Slate 900
        self.rect(0, 0, 210, 16, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(248, 250, 252)
        self.set_y(4)
        self.cell(0, 8, "  SecureMailScope | PS 26159 (NTRO) - Complete Technical Documentation", 0, 0, "L")
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, "Confidential & Engineering Blueprint  ", 0, 1, "R")
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, f"Page {self.page_no()} | Smart India Hackathon (SIH 2026) | Generated on {datetime.datetime.now().strftime('%d %b %Y')}", 0, 0, "C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(30, 58, 138) # Blue 900
        self.set_fill_color(239, 246, 255) # Blue 50
        self.cell(0, 8, f"  {title}", 0, 1, "L", fill=True)
        self.ln(2)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(15, 23, 42)
        self.cell(0, 6, title, 0, 1, "L")

    def body_text(self, text):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(51, 65, 85)
        self.multi_cell(0, 4.5, text)
        self.ln(1.5)

    def key_value(self, key, value):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(30, 41, 59)
        self.cell(50, 5, f"{key}:", 0, 0)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(71, 85, 105)
        self.cell(0, 5, str(value), 0, 1)

def build_pdf(output_path="SecureMailScope_Complete_Project_Overview.pdf"):
    pdf = ProjectDocumentationPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(12, 18, 12)
    
    # -------------------------------------------------------------
    # PAGE 1: Cover & Executive Summary
    # -------------------------------------------------------------
    pdf.add_page()
    
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "SecureMailScope", 0, 1, "C")
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(37, 99, 235)
    pdf.cell(0, 6, "AI-Assisted Cryptographic Security Posture Assessment for Secure Email", 0, 1, "C")
    
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 5, "Smart India Hackathon (SIH 2026) | National Technical Research Organisation (NTRO)", 0, 1, "C")
    pdf.ln(4)

    pdf.section_title("1. Problem Statement Details")
    pdf.key_value("Problem Statement ID", "26159")
    pdf.key_value("Organization", "National Technical Research Organisation (NTRO)")
    pdf.key_value("Category / Theme", "Software / Blockchain & Cybersecurity")
    pdf.key_value("Core Focus", "Passive PCAP Forensics, TLS/X.509 Audit, AI Posture Scoring")
    pdf.ln(2)

    pdf.section_title("2. Executive Summary & Core Objective")
    pdf.body_text(
        "SecureMailScope is an enterprise-grade, passive network forensic framework designed to automatically evaluate "
        "the cryptographic security posture of SMTP, IMAP, and POP3 communications from raw network captures (.pcap / .pcapng). "
        "While traditional packet tools like Wireshark provide packet-level decoding, they do not automatically quantify "
        "cryptographic vulnerabilities or prioritize remediation for SOC analysts.\n\n"
        "SecureMailScope bridges this gap by combining deterministic protocol/crypto rule checking (NIST SP 800-52r2) "
        "with unsupervised Machine Learning (Isolation Forest) for TLS anomaly detection, scoring email sessions on a 0-100 scale "
        "(Grades A+ to F) and generating one-click exportable forensic audit reports (PDF/JSON)."
    )

    pdf.section_title("3. Key Architectural Vectors")
    pdf.key_value("1. Email Protocol Identification", "SMTP (25/587), SMTPS (465), IMAP (143), IMAPS (993), POP3 (110), POP3S (995)")
    pdf.key_value("2. State Transition Tracking", "Cleartext detection, STARTTLS negotiation, STARTTLS downgrade / stripping")
    pdf.key_value("3. TLS Handshake Dissection", "TLS 1.0, 1.1, 1.2, 1.3, SSLv2/v3, Cipher suites, Ephemeral Key Exchange (PFS)")
    pdf.key_value("4. X.509 Certificate Audit", "Expiration dates, Self-signed root, Key length (RSA < 2048-bit), Weak signatures")
    pdf.key_value("5. AI/ML Risk Engine", "Isolation Forest outlier scoring + NIST SP 800-52r2 compliance grading")
    pdf.key_value("6. Executive Dashboards", "Streamlit dark-mode SOC dashboard with one-click JSON/PDF export")

    # -------------------------------------------------------------
    # PAGE 2: Architecture & Codebase Breakdown
    # -------------------------------------------------------------
    pdf.add_page()
    pdf.section_title("4. System Architecture & Forensic Pipeline")
    
    pipeline_diagram = (
        "  [ PCAP Network Capture File (.pcap / .pcapng) ]\n"
        "                     |\n"
        "                     v\n"
        "  +--------------------------------------------------------+\n"
        "  | TCP Stream Reassembler & Protocol Dissector            |\n"
        "  | * 4-Tuple flow reconstruction (SrcIP, Sport, DstIP)    |\n"
        "  | * Email classifier (SMTP / IMAP / POP3)                |\n"
        "  | * STARTTLS state transition & Auth credential monitor  |\n"
        "  +--------------------------+-----------------------------+\n"
        "                             |\n"
        "                             v\n"
        "  +--------------------------------------------------------+\n"
        "  | Cryptographic & X.509 Forensic Engine                  |\n"
        "  | * TLS Record Layer decoder (ClientHello / ServerHello) |\n"
        "  | * NIST SP 800-52r2 cipher suite lookup (PFS / AEAD)    |\n"
        "  | * X.509 Certificate Parser (DER / ASN.1 / Expiration)   |\n"
        "  +--------------------------+-----------------------------+\n"
        "                             |\n"
        "                             v\n"
        "  +--------------------------------------------------------+\n"
        "  | AI Posture Evaluation & Anomaly Scoring Engine         |\n"
        "  | * Isolation Forest unsupervised anomaly classifier     |\n"
        "  | * Rule-based posture scoring (0-100 scale & Grade A-F) |\n"
        "  | * Threat prioritization & automated remediation advice |\n"
        "  +--------------------------+-----------------------------+\n"
        "                             |\n"
        "                             v\n"
        "  [ Interactive Streamlit UI ]  <--->  [ JSON / PDF Forensic Reports ]"
    )
    pdf.set_font("Courier", "", 7.5)
    pdf.set_text_color(15, 23, 42)
    pdf.set_fill_color(241, 245, 249)
    pdf.multi_cell(0, 3.8, pipeline_diagram, 1, "L", fill=True)
    pdf.ln(3)

    pdf.section_title("5. Core Modules & Implementation Files")
    pdf.sub_title("- analyzer.py (Stream & Protocol Dissector)")
    pdf.body_text("Reconstructs TCP streams, identifies mail application ports, checks for plaintext credentials (AUTH LOGIN leaks), parses multi-record TLS handshakes, and decodes ASN.1 DER certificates.")
    
    pdf.sub_title("- ciphers_db.py (Cryptographic Taxonomy)")
    pdf.body_text("Complete IANA database mapping cipher suite hexadecimal IDs to encryption algorithms, MACs, Forward Secrecy (PFS), and NIST SP 800-52r2 ratings (Secure, Warning, Critical).")
    
    pdf.sub_title("- evaluator.py (AI & Compliance Engine)")
    pdf.body_text("Applies compliance rules (RFC 8996, RFC 8461) to deduct weighted penalties and computes Isolation Forest anomaly scores across session feature vectors.")
    
    pdf.sub_title("- generate_samples.py (Synthetic PCAP Generator)")
    pdf.body_text("Generates realistic synthetic PCAP files simulating cleartext leaks, obsolete TLS 1.0, expired certificates, and hardened TLS 1.3 for offline verification.")

    pdf.sub_title("- reporter.py & app.py (Reporting & SOC Dashboard)")
    pdf.body_text("Produces structured JSON feeds and executive PDF audit reports, integrated into a reactive Streamlit web dashboard.")

    # -------------------------------------------------------------
    # PAGE 3: Test Scenarios, Presentation Deck & Quickstart
    # -------------------------------------------------------------
    pdf.add_page()
    pdf.section_title("6. Forensic Test Scenarios & Verified Results")
    
    test_results_text = (
        "1. Insecure Plaintext SMTP with Credential Leak:\n"
        "   - Traffic: Port 25 cleartext session with base64 'AUTH LOGIN'\n"
        "   - Findings: [Critical] Plaintext communication + [Critical] Credentials exposed\n"
        "   - Verified Score: 0/100 [Grade F - Critical]\n\n"
        "2. Obsolete TLS 1.0 + Broken RC4-MD5 Cipher:\n"
        "   - Traffic: Port 587 STARTTLS upgrade to TLS 1.0 with static RSA\n"
        "   - Findings: [High] Obsolete TLS version (RFC 8996) + [Critical] Broken RC4 + [High] No PFS\n"
        "   - Verified Score: 0/100 [Grade F - Critical]\n\n"
        "3. IMAPS with Expired, Self-Signed & Weak 1024-bit RSA Key:\n"
        "   - Traffic: Port 993 Implicit TLS with flawed X.509 certificate\n"
        "   - Findings: [High] Expired cert + [Medium] Self-signed + [High] Weak 1024-bit key\n"
        "   - Verified Score: 20/100 [Grade F - Critical]\n\n"
        "4. Fully Hardened Modern SMTPS:\n"
        "   - Traffic: Port 465 Implicit TLS with TLS 1.3, AES-256-GCM, and ECDHE key exchange\n"
        "   - Findings: Full compliance with NIST SP 800-52r2 standards\n"
        "   - Verified Score: 80-100/100 [Grade A - Secure]"
    )
    pdf.body_text(test_results_text)
    pdf.ln(1)

    pdf.section_title("7. 5-Slide Pitch Deck Summary for NTRO Evaluation")
    pdf.body_text(
        "- Slide 1: The Problem - Email crypto misconfigurations expose critical infrastructures; Wireshark lacks automated posture scoring.\n"
        "- Slide 2: The Solution - SecureMailScope passive stream forensics, TLS/cert deep inspection, and AI threat scoring.\n"
        "- Slide 3: Architecture - Ingestion -> TCP Reassembly -> TLS/X.509 Extraction -> Isolation Forest ML -> Remediation.\n"
        "- Slide 4: Prototype Proof - Live verification across Plaintext, Deprecated TLS 1.0, Expired Certs, and Hardened TLS 1.3.\n"
        "- Slide 5: Value & Future Scope - Zero-overhead passive monitoring, MTA-STS/DANE compliance, and Post-Quantum readiness."
    )

    pdf.section_title("8. How to Run & Replicate the Project")
    pdf.body_text(
        "1. Install Dependencies:   pip install -r requirements.txt\n"
        "2. Generate Test PCAPs:    python generate_samples.py\n"
        "3. Run Pipeline Audit:     python verify_pipeline.py\n"
        "4. Start SOC Dashboard:    streamlit run app.py\n"
        "5. Access UI in Browser:   http://localhost:8501"
    )

    pdf.output(output_path)
    return output_path

if __name__ == "__main__":
    out = build_pdf()
    print(f"Successfully generated complete documentation PDF: {out}")
