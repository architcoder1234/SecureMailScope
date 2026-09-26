"""
SecureMailScope - SIH 2026 Presentation Generator (.pptx)
Builds an executive-ready, highly polished 6-slide PowerPoint deck for NTRO PS 26159.
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_presentation(output_file="SecureMailScope_Presentation.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5) # 16:9 Widescreen

    # Color Palette (Dark Cybersecurity Theme)
    BG_DARK = RGBColor(15, 23, 42)      # Slate 900
    CARD_BG = RGBColor(30, 41, 59)      # Slate 800
    CARD_BORDER = RGBColor(51, 65, 85)  # Slate 700
    ACCENT_BLUE = RGBColor(56, 189, 248) # Sky 400
    ACCENT_GOLD = RGBColor(251, 191, 36) # Amber 400
    ACCENT_GREEN = RGBColor(52, 211, 153) # Emerald 400
    ACCENT_RED = RGBColor(248, 113, 113)  # Red 400
    TEXT_LIGHT = RGBColor(248, 250, 252) # White
    TEXT_MUTED = RGBColor(148, 163, 184) # Slate 400

    def set_slide_background(slide):
        background = slide.background
        fill = background.fill
        fill.solid()
        fill.fore_color.rgb = BG_DARK

    def add_header(slide, title_text, category_text="NTRO | PS #26159 | Blockchain & Cybersecurity"):
        # Category label
        tb_cat = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.3))
        tf_cat = tb_cat.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(10)
        p_cat.font.bold = True
        p_cat.font.color.rgb = ACCENT_BLUE

        # Main Title
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.6))
        tf_title = tb_title.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_LIGHT

    def add_card(slide, left, top, width, height, title, content_list, title_color=ACCENT_BLUE):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
        shape.fill.solid()
        shape.fill.fore_color.rgb = CARD_BG
        shape.line.color.rgb = CARD_BORDER
        shape.line.width = Pt(1.5)

        tf = shape.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.2)
        tf.margin_bottom = Inches(0.2)

        # Title
        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(14)
        p_t.font.bold = True
        p_t.font.color.rgb = title_color
        p_t.space_after = Pt(8)

        # Bullets
        for item in content_list:
            p = tf.add_paragraph()
            p.text = f"• {item}"
            p.font.size = Pt(10.5)
            p.font.color.rgb = TEXT_LIGHT
            p.space_after = Pt(4)

    # -------------------------------------------------------------
    # SLIDE 1: Title Slide (Cover)
    # -------------------------------------------------------------
    slide1 = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background(slide1)

    # Hero Banner box
    hero = slide1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.0), Inches(1.2), Inches(11.33), Inches(5.0))
    hero.fill.solid()
    hero.fill.fore_color.rgb = CARD_BG
    hero.line.color.rgb = ACCENT_BLUE
    hero.line.width = Pt(2)

    tf1 = hero.text_frame
    tf1.word_wrap = True
    tf1.margin_left = Inches(0.6)
    tf1.margin_top = Inches(0.6)

    p1 = tf1.paragraphs[0]
    p1.text = "SMART INDIA HACKATHON 2026"
    p1.font.size = Pt(13)
    p1.font.bold = True
    p1.font.color.rgb = ACCENT_GOLD
    p1.space_after = Pt(12)

    p2 = tf1.add_paragraph()
    p2.text = "SecureMailScope"
    p2.font.size = Pt(36)
    p2.font.bold = True
    p2.font.color.rgb = TEXT_LIGHT
    p2.space_after = Pt(8)

    p3 = tf1.add_paragraph()
    p3.text = "AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications"
    p3.font.size = Pt(16)
    p3.font.color.rgb = ACCENT_BLUE
    p3.space_after = Pt(24)

    p4 = tf1.add_paragraph()
    p4.text = "Organization: National Technical Research Organisation (NTRO) | Problem Statement ID: 26159"
    p4.font.size = Pt(12)
    p4.font.color.rgb = TEXT_MUTED

    p5 = tf1.add_paragraph()
    p5.text = "Theme: Blockchain & Cybersecurity | Category: Software"
    p5.font.size = Pt(12)
    p5.font.color.rgb = TEXT_MUTED

    # -------------------------------------------------------------
    # SLIDE 2: The Problem & The Forensic Gap
    # -------------------------------------------------------------
    slide2 = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background(slide2)
    add_header(slide2, "Problem Context & The Forensic Analysis Gap")

    add_card(slide2, 0.8, 1.5, 3.7, 5.3, "1. Enterprise Email Vulnerability", [
        "Email (SMTP, IMAP, POP3) is the primary critical communication backbone.",
        "Widespread silent misconfigurations exist in enterprise email servers.",
        "Obsolete TLS 1.0/1.1 protocols remain active on legacy mail relays.",
        "Broken ciphers (RC4, 3DES, CBC) expose traffic to POODLE & BEAST attacks.",
        "Missing Forward Secrecy (PFS) allows past email traffic to be retroactively decrypted."
    ], ACCENT_RED)

    add_card(slide2, 4.8, 1.5, 3.7, 5.3, "2. The Limitation of Packet Tools", [
        "Tools like Wireshark and tcpdump provide packet decoding, but ZERO security posture scoring.",
        "No automated evaluation against NIST SP 800-52r2 standards.",
        "Security Operations Centers (SOC) must manually inspect hundreds of packet streams.",
        "Subtle STARTTLS stripping and downgrade attacks go unnoticed.",
        "No automated remediation guidance for email administrators."
    ], ACCENT_GOLD)

    add_card(slide2, 8.8, 1.5, 3.7, 5.3, "3. The SecureMailScope Innovation", [
        "100% Passive Network Forensic Framework operating directly on PCAP captures.",
        "Reconstructs TCP email streams and validates STARTTLS negotiation transitions.",
        "Deep X.509 Certificate auditing (Validity, Key Length, Self-signed root).",
        "Deterministic Rule Engine + AI Isolation Forest anomaly detection.",
        "Automated 0-100 posture scoring with exportable JSON, PDF, and HTML audit reports."
    ], ACCENT_GREEN)

    # -------------------------------------------------------------
    # SLIDE 3: System Architecture & Technical Pipeline
    # -------------------------------------------------------------
    slide3 = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background(slide3)
    add_header(slide3, "System Architecture & 5-Stage Forensic Pipeline")

    add_card(slide3, 0.8, 1.5, 5.6, 2.5, "Stage 1: TCP & Protocol Reconstruction", [
        "4-Tuple Flow Grouping: (Src IP, Src Port, Dst IP, Dst Port).",
        "Protocol Classifier: SMTP (25/587), SMTPS (465), IMAP (143/993), POP3 (110/995).",
        "Cleartext Credential Monitor: Detects exposed AUTH LOGIN / AUTH PLAIN passwords."
    ], ACCENT_BLUE)

    add_card(slide3, 6.8, 1.5, 5.6, 2.5, "Stage 2: TLS Handshake & Cipher Dissection", [
        "Parses multi-record TLS Handshakes (ClientHello & ServerHello).",
        "Version Resolver: SSL 2/3, TLS 1.0, 1.1, 1.2, and TLS 1.3.",
        "NIST SP 800-52r2 Mapping: Evaluates AEAD ciphers, MAC algorithms, and PFS."
    ], ACCENT_BLUE)

    add_card(slide3, 0.8, 4.3, 5.6, 2.5, "Stage 3: X.509 Certificate Chain Inspection", [
        "ASN.1 DER Parser: Extracts Subject, Issuer, Validity Dates, and Key Type.",
        "Vulnerability Checks: Expired certs, Untrusted Self-signed roots, Weak RSA < 2048-bit.",
        "Signature Hash Validation: Flags broken MD5 and SHA-1 signatures."
    ], ACCENT_GOLD)

    add_card(slide3, 6.8, 4.3, 5.6, 2.5, "Stage 4 & 5: AI Scoring & Tri-Format Reporting", [
        "Rules First, AI Second: Deterministic posture scoring (0-100 & Grade A+ to F).",
        "Isolation Forest ML: Unsupervised multi-dimensional TLS anomaly detection.",
        "Tri-Format Export: One-click export for JSON (SIEM), PDF (Executive), and HTML (Web)."
    ], ACCENT_GREEN)

    # -------------------------------------------------------------
    # SLIDE 4: Empirical Verification & Prototype Results
    # -------------------------------------------------------------
    slide4 = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background(slide4)
    add_header(slide4, "Empirical Verification Across Live Test Scenarios")

    add_card(slide4, 0.8, 1.5, 5.6, 2.5, "Test 1: Plaintext SMTP (Port 25)", [
        "Traffic: Plaintext SMTP with Base64 AUTH LOGIN command.",
        "Detected Flaws: [Critical] Unencrypted plain stream + [Critical] Password leak.",
        "Posture Result: Score 0 / 100 [Grade F - Critical Vulnerability]."
    ], ACCENT_RED)

    add_card(slide4, 6.8, 1.5, 5.6, 2.5, "Test 2: Obsolete TLS 1.0 + RC4 (Port 587)", [
        "Traffic: STARTTLS upgrade to deprecated TLS 1.0 with static RSA.",
        "Detected Flaws: [High] RFC 8996 violation + [Critical] Broken RC4 + [High] No PFS.",
        "Posture Result: Score 0 / 100 [Grade F - Critical Vulnerability]."
    ], ACCENT_RED)

    add_card(slide4, 0.8, 4.3, 5.6, 2.5, "Test 3: IMAPS with Expired & Weak Cert (Port 993)", [
        "Traffic: TLS 1.2 session with flawed X.509 digital certificate.",
        "Detected Flaws: [High] Expired cert + [Medium] Self-signed + [High] Weak 1024-bit RSA.",
        "Posture Result: Score 20 / 100 [Grade F - Critical Vulnerability]."
    ], ACCENT_GOLD)

    add_card(slide4, 6.8, 4.3, 5.6, 2.5, "Test 4: Fully Hardened Modern SMTPS (Port 465)", [
        "Traffic: Implicit TLS with modern TLS 1.3 + AES-256-GCM + ECDHE.",
        "Compliance: Fully compliant with NIST SP 800-52r2 standards.",
        "Posture Result: Score 80-100 / 100 [Grade A - Secure & Compliant]."
    ], ACCENT_GREEN)

    # -------------------------------------------------------------
    # SLIDE 5: SOC Dashboard & Actionable Remediation
    # -------------------------------------------------------------
    slide5 = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background(slide5)
    add_header(slide5, "Interactive SOC Dashboard & Remediation Workflow")

    add_card(slide5, 0.8, 1.5, 5.6, 5.3, "Interactive SOC Capabilities", [
        "Live Ingestion: Drag-and-drop custom PCAP/PCAPNG or choose synthetic demo scenarios.",
        "Visual Posture Analytics: Pie charts for encryption mode distribution & posture bar charts.",
        "Stream Inspector: Deep session drilldowns displaying client/server endpoints and timings.",
        "Certificate Chain Viewer: Color-coded validity badges and public key metadata inspection.",
        "Real-Time Telemetry: Total packets, email streams, weak ciphers, and cert flaw counters."
    ], ACCENT_BLUE)

    add_card(slide5, 6.8, 1.5, 5.6, 5.3, "Prioritized Remediation & Impact", [
        "Direct Finding-to-Fix Linking: Every penalty links to an actionable mitigation step.",
        "Automated Policy Recommendations: Guidance on enforcing MTA-STS (RFC 8461) and DANE (RFC 7672).",
        "Eliminates Manual Triage: Reduces forensic investigation from hours to under 2 seconds.",
        "SIEM & Data Lake Integration: Standardized JSON outputs for Splunk, Elastic, and OpenSearch.",
        "Air-Gapped Operation: Runs 100% offline with zero external network or cloud calls."
    ], ACCENT_GREEN)

    # -------------------------------------------------------------
    # SLIDE 6: Compliance, Value & Future Scope
    # -------------------------------------------------------------
    slide6 = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background(slide6)
    add_header(slide6, "Compliance Standards, Impact & Future Roadmap")

    add_card(slide6, 0.8, 1.5, 5.6, 5.3, "Standards Compliance & Verification", [
        "NIST SP 800-52 Rev 2: Guidelines for TLS Implementations.",
        "RFC 8996: Formal Deprecation of SSL 2.0/3.0 & TLS 1.0/1.1.",
        "RFC 8461: SMTP Mail Transfer Agent Strict Transport Security (MTA-STS).",
        "RFC 7672: SMTP Security via Opportunistic DANE-TLS.",
        "Explainable AI: Isolation Forest anomaly confidence score prevents black-box errors."
    ], ACCENT_GOLD)

    add_card(slide6, 6.8, 1.5, 5.6, 5.3, "Strategic Impact & Future Roadmap", [
        "Zero-Overhead Gateway Auditing: Seamless passive tap on enterprise mail relays.",
        "10Gbps+ Line-Rate Sniffing: Transitioning parser to DPDK / AF_PACKET kernel bypass.",
        "Post-Quantum Cryptography (PQC) Readiness: Scoring transition to ML-KEM (Kyber) & ML-DSA (Dilithium).",
        "MTA-STS Policy Auto-Enforcement: Automated DNS and policy generation.",
        "Tamper-Evident Report Ledger: SHA-256 cryptographic chain of custody for forensics."
    ], ACCENT_BLUE)

    prs.save(output_file)
    return output_file

if __name__ == "__main__":
    out = create_presentation()
    print(f"Successfully generated PowerPoint presentation: {out}")
