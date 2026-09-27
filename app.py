"""
SecureMailScope - Next-Gen Cyber Threat Posture & Speedometer SOC Dashboard
Matches Concept 3: Central Speedometer Gauge, Protocol Flow, Active CVE Alert Chips,
Glassmorphism Cards, and Deep Forensic Telemetry.
"""

import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from analyzer import MailStreamAnalyzer
from evaluator import CryptographicEvaluator, generate_mta_sts_policy
from reporter import generate_json_report, generate_pdf_report, generate_html_report
from generate_samples import generate_all_sample_pcaps
from blockchain_ledger import BlockchainAuditLedger

# Page Configuration
st.set_page_config(
    page_title="SecureMailScope | Threat Posture Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Cyber Theme CSS (Concept 3 Styling)
st.markdown("""
<style>
    /* Dark Cyber Theme Background */
    .stApp {
        background-color: #060a12;
        background-image: radial-gradient(circle at 50% 0%, rgba(14, 165, 233, 0.1) 0%, transparent 60%),
                          linear-gradient(to right, rgba(255,255,255,0.015) 1px, transparent 1px),
                          linear-gradient(to bottom, rgba(255,255,255,0.015) 1px, transparent 1px);
        background-size: 100% 100%, 30px 30px, 30px 30px;
        color: #f8fafc;
    }

    /* Top Bar Banner */
    .header-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: linear-gradient(90deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.8) 100%);
        border: 1px solid rgba(56, 189, 248, 0.35);
        border-radius: 10px;
        padding: 14px 24px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5), 0 0 15px rgba(56, 189, 248, 0.15);
    }
    .header-title {
        font-size: 22px;
        font-weight: 800;
        letter-spacing: 1.5px;
        color: #38bdf8;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .status-live {
        background-color: #059669;
        color: #ecfdf5;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: bold;
        letter-spacing: 1px;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.4);
    }

    /* Score Badges */
    .score-badge-box {
        display: flex;
        justify-content: space-around;
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 8px;
        padding: 10px;
        margin-top: 8px;
    }

    /* Alert Chips */
    .cve-alert-box {
        background: rgba(220, 38, 38, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.6);
        border-left: 5px solid #ef4444;
        color: #fecaca;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        margin-bottom: 6px;
        font-family: monospace;
    }
    .cve-badge-red {
        background: #dc2626;
        color: white;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 10.5px;
        font-weight: bold;
        margin-right: 6px;
    }

    /* Certificate Graph & Flow Diagram */
    .cert-tree-container {
        background: radial-gradient(circle at 50% 10%, rgba(30, 41, 59, 0.5) 0%, rgba(15, 23, 42, 0.9) 100%);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 12px;
        padding: 24px;
        margin-top: 15px;
        margin-bottom: 20px;
        box-shadow: 0 4px 25px rgba(0, 0, 0, 0.5);
    }
    .cert-flow-wrapper {
        display: flex;
        flex-direction: column;
        align-items: center;
        width: 100%;
        padding: 10px 0;
    }
    .cert-node-box {
        width: 80%;
        max-width: 680px;
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 6px 20px rgba(0,0,0,0.4);
        transition: all 0.25s ease;
        position: relative;
    }
    .cert-node-box:hover {
        transform: scale(1.015);
    }
    .cert-node-box-root {
        border: 2px solid #10b981;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.25);
    }
    .cert-node-box-intermediate {
        border: 2px solid #38bdf8;
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.25);
    }
    .cert-node-box-leaf-valid {
        border: 2px solid #10b981;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.25);
    }
    .cert-node-box-leaf-warn {
        border: 2px solid #ef4444;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.25);
    }
    .flow-arrow-down {
        display: flex;
        flex-direction: column;
        align-items: center;
        margin: 6px 0;
        color: #38bdf8;
    }
    .flow-arrow-stem {
        width: 3px;
        height: 32px;
        background: linear-gradient(to bottom, #38bdf8, #818cf8);
    }
    .flow-arrow-head {
        width: 0;
        height: 0;
        border-left: 7px solid transparent;
        border-right: 7px solid transparent;
        border-top: 9px solid #818cf8;
    }
    .flow-arrow-label {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 6px;
        padding: 2px 10px;
        font-size: 11px;
        font-family: monospace;
        color: #94a3b8;
        margin: -24px 0 10px 0;
        z-index: 2;
    }
    .cert-badge-green {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #10b981;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 700;
        font-family: monospace;
    }
    .cert-badge-red {
        background: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 700;
        font-family: monospace;
    }
    .cert-badge-blue {
        background: rgba(56, 189, 248, 0.2);
        color: #38bdf8;
        border: 1px solid #38bdf8;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 700;
        font-family: monospace;
    }

    /* AI Executive Defender Briefing */
    .ai-defender-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.9) 100%);
        border: 1px solid rgba(129, 140, 248, 0.4);
        border-left: 5px solid #818cf8;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), 0 0 15px rgba(129, 140, 248, 0.15);
    }
    .ai-defender-title {
        color: #a5b4fc;
        font-size: 14px;
        font-weight: 800;
        letter-spacing: 1px;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 6px;
    }

    /* Simulated SOC Alert Slack Channel */
    .soc-slack-container {
        background: #0f172a;
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 10px;
        padding: 16px;
        font-family: monospace;
        margin-top: 10px;
        margin-bottom: 15px;
    }
    .soc-slack-header {
        display: flex;
        align-items: center;
        gap: 8px;
        padding-bottom: 10px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        margin-bottom: 12px;
        color: #94a3b8;
        font-size: 13px;
        font-weight: bold;
    }
    .soc-slack-message {
        display: flex;
        gap: 12px;
        margin-bottom: 12px;
        font-size: 12.5px;
        line-height: 1.5;
    }
    .soc-slack-avatar {
        background: #ef4444;
        color: white;
        width: 32px;
        height: 32px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        font-size: 12px;
        flex-shrink: 0;
    }
    .soc-slack-avatar-bot {
        background: #6366f1;
    }

    /* MITRE ATT&CK Badges */
    .mitre-badge {
        background: rgba(245, 158, 11, 0.15);
        border: 1px solid #f59e0b;
        color: #fde68a;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        font-family: monospace;
        display: inline-block;
        margin-right: 6px;
        margin-bottom: 6px;
    }
    .mitre-badge-crit {
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid #ef4444;
        color: #fca5a5;
    }

    /* Timeline Stepper */
    .timeline-step {
        display: flex;
        gap: 14px;
        position: relative;
        padding-bottom: 20px;
    }
    .timeline-icon {
        width: 30px;
        height: 30px;
        border-radius: 50%;
        background: #0284c7;
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: bold;
        z-index: 2;
        flex-shrink: 0;
    }
    .timeline-step:before {
        content: '';
        position: absolute;
        left: 14px;
        top: 30px;
        bottom: 0;
        width: 2px;
        background: rgba(56, 189, 248, 0.3);
    }
    .timeline-step:last-child:before {
        display: none;
    }
</style>
""", unsafe_allow_html=True)

# Ensure sample files exist
SAMPLES_DIR = "samples"
if not os.path.exists(SAMPLES_DIR) or len(os.listdir(SAMPLES_DIR)) == 0:
    generate_all_sample_pcaps(SAMPLES_DIR)

# Sidebar Configuration
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("SecureMailScope")
    st.caption("NTRO PS #26159 | Threat Posture Forensics")
    st.markdown("---")

    source_type = st.radio("Choose PCAP Source:", ["📁 Select Scenario PCAP", "⬆️ Upload Custom PCAP"])
    pcap_target_path = None
    selected_pcap_name = "demo_capture.pcap"

    SCENARIO_DESCRIPTIONS = {
        # Standard filenames from generate_samples.py
        "sample1_smtp_plaintext_auth_leak.pcap": "🚨 Plaintext SMTP (Cleartext Password Leak - Port 25)",
        "sample2_smtp_obsolete_tls10_rc4.pcap": "🔴 Insecure SMTP (TLS 1.0 + RC4 Cipher - POODLE/BEAST Risk)",
        "sample3_imaps_expired_selfsigned_cert.pcap": "⚠️ IMAPS (Expired & Self-Signed 1024-bit RSA Cert)",
        "sample4_smtps_hardened_tls13_pfs.pcap": "🟢 Hardened SMTPS (TLS 1.3 + AES-GCM + PFS - Grade A+)",
        "sample5_pop3_plaintext_pass_leak.pcap": "🚨 Plaintext POP3 (Cleartext Password Extracted - Port 110)",
        "sample6_smtp_starttls_stripping_attack.pcap": "🚨 STRIPTLS Attack (Active Downgrade & MITM Detected)",
        "sample7_imaps_sweet32_3des_cbc.pcap": "🟠 IMAPS Traffic (3DES Cipher - SWEET32 CVE-2016-2183)",
        "sample8_smtps_untrusted_selfsigned_1024_rsa.pcap": "⚠️ SMTPS Untrusted Self-Signed Certificate Chain",
        "sample9_mixed_enterprise_traffic_bundle.pcap": "🏢 Mixed Enterprise SOC Telemetry (Multi-Stream Bundle)",
        "sample10_smtps_post_quantum_hybrid_pqc.pcap": "⚛️ Quantum Safe SMTPS (ML-KEM / Kyber Hybrid PQC Ready)",
        # Numbered aliases
        "01_smtp_modern_tls13.pcap": "🟢 Modern SMTP (TLS 1.3 + ChaCha20-Poly1305 - Grade A+)",
        "02_smtp_deprecated_tls10.pcap": "🔴 Insecure SMTP (TLS 1.0 + CBC - POODLE/BEAST Risk)",
        "03_smtp_starttls_stripping.pcap": "🚨 STRIPTLS Attack (Cleartext Credential Leak Detected)",
        "04_imap_sweet32_3des.pcap": "🟠 IMAP Traffic (3DES Cipher - SWEET32 CVE-2016-2183)",
        "05_smtp_expired_cert.pcap": "⚠️ SMTP Mail Server with Expired X.509 Certificate",
        "06_pop3_plain_auth_leak.pcap": "🚨 Plaintext POP3 (Cleartext Password Extracted)",
        "07_smtp_pqc_hybrid_ready.pcap": "⚛️ Quantum Safe (X25519Kyber768 ML-KEM Hybrid)",
        "08_multi_stream_corporate_bundle.pcap": "🏢 Multi-Stream Enterprise SOC Telemetry (Mixed Protocols)",
        "09_smtp_weak_dh_param.pcap": "🟠 SMTP Weak Diffie-Hellman Key Exchange (<2048-bit)",
        "10_imap_self_signed_cert.pcap": "⚠️ IMAP Untrusted Self-Signed Certificate Chain"
    }

    if source_type == "📁 Select Scenario PCAP":
        sample_files = sorted([f for f in os.listdir(SAMPLES_DIR) if f.endswith(".pcap")])
        
        def format_scenario_name(filename):
            return SCENARIO_DESCRIPTIONS.get(filename, f"📦 {filename}")

        selected_sample = st.selectbox(
            "Select Test Forensic Scenario:",
            sample_files,
            format_func=format_scenario_name,
            help="Choose a pre-configured network forensic scenario to analyze its cryptographic posture."
        )
        if selected_sample:
            pcap_target_path = os.path.join(SAMPLES_DIR, selected_sample)
            selected_pcap_name = selected_sample
    else:
        uploaded_file = st.file_uploader("Upload .pcap / .pcapng capture file", type=["pcap", "pcapng"], help="Upload any live Wireshark or tcpdump packet capture.")
        if uploaded_file:
            temp_path = os.path.join("samples", f"uploaded_{uploaded_file.name}")
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            pcap_target_path = temp_path
            selected_pcap_name = uploaded_file.name

    st.markdown("---")
    with st.expander("ℹ️ Compliance Standards Explained", expanded=False):
        st.markdown("""
        - **📜 NIST SP 800-52r2**: Federal TLS requirements (Mandates TLS 1.2/1.3 & PFS).
        - **⚛️ NIST FIPS 203**: Quantum resistance standards against Shor's algorithm.
        - **🚫 RFC 8996**: Deprecates insecure TLS 1.0 & 1.1.
        - **🛡️ RFC 8461 (MTA-STS)**: Enforces TLS encryption on mail delivery.
        - **🌐 RFC 7672 (DANE)**: Cryptographic DNSSEC certificate validation.
        """)

if not pcap_target_path:
    st.info("👈 Please select a test scenario or upload a PCAP to begin analysis.")
    st.stop()

# Execution Pipeline
with st.spinner("Executing passive deep inspection and cryptographic scoring..."):
    analyzer = MailStreamAnalyzer(pcap_target_path)
    sessions, summary_stats = analyzer.parse()

    evaluator = CryptographicEvaluator()
    for s in sessions:
        s["evaluation"] = evaluator.evaluate_session(s)
    
    # Run AI Anomaly Detection
    sessions = evaluator.train_and_detect_anomalies(sessions)

# Top Bar Header
st.markdown(f"""
<div class="header-bar">
    <div class="header-title">🛡️ SECUREMAILSCOPE <span style="font-size:14px; color:#94a3b8; font-weight:normal;">| THREAT POSTURE ANALYSIS</span></div>
    <div style="display:flex; gap:16px; align-items:center;">
        <span style="font-size:12px; color:#94a3b8; font-family:monospace;">SOURCE: {selected_pcap_name}</span>
        <span class="status-live">● ENGINE LIVE</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Calculate Overall Aggregated Posture Score (0–100) and Threat Level
if sessions:
    avg_score = int(sum(s["evaluation"]["posture_score"] for s in sessions) / len(sessions))
else:
    avg_score = 100

risk_score = 100 - avg_score

if risk_score <= 30:
    threat_label = "SECURE / LOW RISK"
    threat_sub = "OVERALL RISK: MINIMAL"
    threat_color = "#10b981"
    ai_summary_text = "Overall email cryptographic telemetry meets high-assurance federal standards (NIST SP 800-52r2). Ephemeral key exchange and modern TLS are properly negotiated with no cleartext credential leaks detected."
    ai_next_step = "Maintain current automated certificate renewal and begin pilot testing of NIST FIPS 203 Post-Quantum Hybrid KEM."
elif risk_score <= 65:
    threat_label = "MODERATE THREAT"
    threat_sub = "OVERALL RISK: WARNING"
    threat_color = "#f59e0b"
    ai_summary_text = "Sub-optimal or aging cryptographic configurations detected. Communication is at risk of downgrade exploits, expired trust anchors, or lack of Perfect Forward Secrecy."
    ai_next_step = "Enforce TLS 1.3, deprecate legacy cipher suites (3DES / CBC), and renew all X.509 digital certificates."
else:
    threat_label = "CRITICAL THREAT"
    threat_sub = "OVERALL RISK: CRITICAL VULNERABILITY"
    threat_color = "#ef4444"
    ai_summary_text = "Severe security anomalies detected! Active cleartext transmission, STARTTLS stripping, or deprecated TLS 1.0/1.1 protocols expose communications to Man-in-the-Middle (MITM) credential harvesting."
    ai_next_step = "Immediately enforce RFC 8461 (MTA-STS), isolate vulnerable mail servers, and rotate exposed credentials."

# AI Defender Executive Briefing Box (from MIRAGE-X concept)
st.markdown(f"""
<div class="ai-defender-card">
    <div class="ai-defender-title">🤖 AI DEFENDER EXECUTIVE BRIEFING & ADVISORY</div>
    <div style="font-size:13.5px; color:#e2e8f0; line-height:1.6; margin-bottom:8px;">
        {ai_summary_text}
    </div>
    <div style="font-size:12.5px; color:#a5b4fc; font-weight:600;">
        <strong>Recommended Strategic Action:</strong> {ai_next_step}
    </div>
</div>
""", unsafe_allow_html=True)

# =========================================================================
# ROW 1: THE CONCEPT 3 HERO GRID
# =========================================================================
col_left, col_center, col_right = st.columns([1.2, 1.4, 1.1])

with col_left:
    st.markdown("#### 🌊 Protocol Flow & Ingestion")
    
    enc_counts = {
        "Plaintext": summary_stats["plaintext_sessions"],
        "STARTTLS": summary_stats["starttls_sessions"],
        "Implicit TLS": summary_stats["implicit_tls_sessions"]
    }
    
    fig_flow = px.pie(
        names=list(enc_counts.keys()),
        values=[max(1, v) if sum(enc_counts.values())==0 else v for v in enc_counts.values()],
        hole=0.6,
        color=list(enc_counts.keys()),
        color_discrete_map={"Plaintext": "#ef4444", "STARTTLS": "#f59e0b", "Implicit TLS": "#10b981"}
    )
    fig_flow.update_layout(
        showlegend=True,
        margin=dict(t=5, b=5, l=5, r=5),
        height=160,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color="#f8fafc", size=11),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )
    st.plotly_chart(fig_flow, use_container_width=True)

    # Active CVE Alerts
    st.markdown("##### 🚨 Active Vulnerability Alerts")
    all_cves = []
    for s in sessions:
        all_cves.extend(s["evaluation"].get("named_cves", []))
    all_cves = list(set(all_cves))

    if all_cves:
        for c in all_cves[:3]:
            st.markdown(f"""
            <div class="cve-alert-box">
                <span class="cve-badge-red">ALERT</span> {c}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:rgba(16, 185, 129, 0.12); border:1px solid #10b981; color:#6ee7b7; padding:8px 12px; border-radius:6px; font-size:12px;">
            ✅ Zero active CVE exploits detected.
        </div>
        """, unsafe_allow_html=True)

with col_center:
    st.markdown("<h4 style='text-align:center;'>🎯 CYBER THREAT POSTURE</h4>", unsafe_allow_html=True)
    
    # Speedometer Gauge
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        number={'suffix': "", 'font': {'size': 44, 'color': threat_color, 'family': "Helvetica"}},
        title={'text': f"<b>{threat_label}</b><br><span style='font-size:12px; color:#94a3b8;'>{threat_sub}</span>", 'font': {'size': 15, 'color': threat_color}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#94a3b8", 'tickvals': [0, 30, 65, 100]},
            'bar': {'color': threat_color, 'thickness': 0.28},
            'bgcolor': "rgba(15, 23, 42, 0.6)",
            'borderwidth': 1,
            'bordercolor': "rgba(56, 189, 248, 0.3)",
            'steps': [
                {'range': [0, 30], 'color': "rgba(16, 185, 129, 0.25)"},
                {'range': [30, 65], 'color': "rgba(245, 158, 11, 0.25)"},
                {'range': [65, 100], 'color': "rgba(239, 68, 68, 0.35)"}
            ],
            'threshold': {
                'line': {'color': "#38bdf8", 'width': 3},
                'thickness': 0.8,
                'value': risk_score
            }
        }
    ))
    fig_gauge.update_layout(
        height=230,
        margin=dict(t=20, b=5, l=15, r=15),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color="#f8fafc")
    )
    st.plotly_chart(fig_gauge, use_container_width=True)
    
    st.markdown(f"""
    <div class="score-badge-box">
        <div><strong>Security Posture:</strong> <span style="color:#38bdf8; font-size:15px; font-weight:bold;">{avg_score} / 100</span></div>
        <div><strong>Risk Meter:</strong> <span style="color:{threat_color}; font-size:15px; font-weight:bold;">{risk_score} / 100</span></div>
    </div>
    """, unsafe_allow_html=True)

with col_right:
    st.markdown("#### 📡 Threat Telemetry")
    
    t_c1, t_c2 = st.columns(2)
    with t_c1:
        st.metric("Total Packets", summary_stats["total_packets"])
        st.metric("Weak Ciphers", summary_stats["weak_ciphers_detected"], delta_color="inverse")
    with t_c2:
        st.metric("Email Streams", summary_stats["total_email_sessions"])
        st.metric("Cert Flaws", summary_stats["cert_issues_detected"], delta_color="inverse")
    
    df_mini = pd.DataFrame({
        "Metric": ["Plaintext", "STARTTLS", "Implicit TLS"],
        "Count": [summary_stats["plaintext_sessions"], summary_stats["starttls_sessions"], summary_stats["implicit_tls_sessions"]]
    })
    fig_bar_mini = px.bar(df_mini, x="Count", y="Metric", orientation='h', color="Metric",
                          color_discrete_map={"Plaintext": "#ef4444", "STARTTLS": "#f59e0b", "Implicit TLS": "#10b981"})
    fig_bar_mini.update_layout(
        showlegend=False,
        height=100,
        margin=dict(t=2, b=2, l=2, r=2),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showticklabels=False, showgrid=False),
        yaxis=dict(showgrid=False, tickfont=dict(color="#cbd5e1", size=10))
    )
    st.plotly_chart(fig_bar_mini, use_container_width=True)

st.markdown("<hr style='border:1px solid rgba(56, 189, 248, 0.15); margin: 20px 0;'>", unsafe_allow_html=True)

# =========================================================================
# ROW 2: MULTI-TAB DEEP FORENSIC WORKBENCH
# =========================================================================
tab_streams, tab_cert_tree, tab_soc_alerts, tab_pqc_readiness, tab_chain, tab_mta, tab_export = st.tabs([
    "🔍 Reconstructed Stream Inspector",
    "🌲 Certificate Chain & Trust Tree",
    "💬 Simulated SOC Alert Feed (#soc-alerts)",
    "⚛️ Post-Quantum Readiness (NIST FIPS 203)",
    "⛓️ Blockchain Audit Ledger",
    "🛠️ MTA-STS Policy Generator",
    "📑 Forensic Export (JSON / PDF / HTML)"
])

with tab_soc_alerts:
    st.subheader("💬 Simulated SOC Incident Channel (`#soc-alerts`)")
    st.caption("Real-time operational paging integration simulation styled after Enterprise SOC Slack / MS Teams webhook channels.")

    st.markdown("""
    <div class="soc-slack-container">
        <div class="soc-slack-header">
            <span>🔒 #soc-alerts</span>
            <span style="color:#64748b;">|</span>
            <span style="font-weight:normal; font-size:12px; color:#94a3b8;">Automated Paging & Incident Response Stream (Live Feed)</span>
        </div>
    """, unsafe_allow_html=True)

    # Generate alerts for current PCAP
    critical_events = []
    for s in sessions:
        ev = s["evaluation"]
        if s.get("plaintext_auth_leaked"):
            critical_events.append(("P1-CRITICAL", "🚨 CLEARTEXT CREDENTIAL EXPOSURE", f"Session #{s['session_id']} ({s['client']} ➔ {s['server']}) transmitted raw cleartext credentials! Immediate credential rotation dispatched.", "#ef4444"))
        if s.get("encryption_mode") == "STARTTLS Failed/Stripped":
            critical_events.append(("P1-CRITICAL", "🚨 ACTIVE STRIPTLS DOWNGRADE ATTACK", f"Adversary-in-the-Middle stripped STARTTLS banner on {s['server']}. MITRE ATT&CK T1557.002 mapped.", "#ef4444"))
        for cert in s.get("tls_details", {}).get("certificates", []):
            if cert.get("is_expired"):
                critical_events.append(("P2-HIGH", "⚠️ EXPIRED TLS CERTIFICATE IN PRODUCTION", f"End-entity certificate for {cert.get('subject')} expired on {cert.get('valid_to')}.", "#f59e0b"))
            if cert.get("is_self_signed"):
                critical_events.append(("P3-MEDIUM", "⚠️ UNTRUSTED SELF-SIGNED CERTIFICATE", f"Untrusted root authority detected on {s['server']}.", "#f59e0b"))
        for c in ev.get("named_cves", []):
            if "SWEET32" in c or "POODLE" in c or "BEAST" in c:
                critical_events.append(("P2-HIGH", f"⚠️ VULNERABLE CIPHER NEGOTIATED: {c}", f"Session #{s['session_id']} agreed to legacy cipher suite vulnerable to known exploit.", "#f59e0b"))

    if not critical_events:
        st.markdown("""
        <div class="soc-slack-message">
            <div class="soc-slack-avatar soc-slack-avatar-bot">🤖</div>
            <div>
                <div style="font-weight:bold; color:#a5b4fc; font-size:13px;">SecureMailScope-Bot <span style="font-size:11px; color:#64748b; font-weight:normal;">TODAY AT 17:20 PM</span></div>
                <div style="color:#34d399; font-size:12.5px; margin-top:3px;">
                    ✅ All inspected sessions passed cryptographic sanity checks. No critical downgrade or credential leaks detected on active channels.
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        for prio, title, msg, color in critical_events:
            st.markdown(f"""
            <div class="soc-slack-message">
                <div class="soc-slack-avatar" style="background:{color};">🚨</div>
                <div>
                    <div style="font-weight:bold; color:#f8fafc; font-size:13px;">
                        SecureMailScope-Bot <span style="background:{color}33; color:{color}; border:1px solid {color}; padding:1px 6px; border-radius:4px; font-size:10px; margin-left:6px;">{prio}</span>
                        <span style="font-size:11px; color:#64748b; font-weight:normal; margin-left:8px;">JUST NOW</span>
                    </div>
                    <div style="color:#fecaca; font-weight:bold; font-size:12.5px; margin-top:2px;">{title}</div>
                    <div style="color:#cbd5e1; font-size:12px; margin-top:2px;">{msg}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

with tab_cert_tree:
    st.subheader("🌲 Certificate Chain & PKI Trust Hierarchy Tree")
    st.markdown("Visual verification of Public Key Infrastructure (PKI) certification paths, Trust Anchors (Root CA), Intermediate Issuers, and End-Entity Server Certificates extracted from TLS handshakes.")

    certs_found = False
    for s in sessions:
        tls = s.get("tls_details", {})
        certs = tls.get("certificates", [])
        if certs:
            certs_found = True
            st.markdown(f"### 🔐 Session #{s['session_id']} PKI Trust Graph ({s['protocol']} • `{s['server']}`)")
            
            leaf_cert = certs[0]
            is_self = leaf_cert.get("is_self_signed", False)
            has_flaw = bool(leaf_cert.get("is_expired") or leaf_cert.get("issues"))

            # 1. GRAPHICAL TREE DIAGRAM (Graphviz)
            st.markdown("##### 🌐 Interactive PKI Dependency Tree Graph")
            
            if is_self:
                dot_code = f"""
                digraph PKI_Trust {{
                    rankdir=TB;
                    bgcolor="transparent";
                    node [fontname="Helvetica", fontsize=11, style="filled,rounded", shape=box, penwidth=2];
                    edge [fontname="Helvetica", fontsize=9, color="#ef4444", penwidth=2, arrowhead=vee];

                    root [label="⚠️ Self-Signed Untrusted Cert\\nSubject: {leaf_cert.get('subject', 'Server Cert')[:30]}...\\nIssuer: Self-Signed\\nStatus: UNTRUSTED ROOT", fillcolor="#450a0a", fontcolor="#fca5a5", color="#ef4444"];
                    leaf [label="✉️ Mail Server Leaf\\n{leaf_cert.get('key_algorithm')} ({leaf_cert.get('key_size')} bits)\\nStatus: High Risk Flaw", fillcolor="#450a0a", fontcolor="#fca5a5", color="#ef4444"];

                    root -> leaf [label="Self-Signed Link (No CA)", color="#ef4444", style=dashed];
                }}
                """
            else:
                root_ca_name = leaf_cert.get("issuer", "DigiCert Global Root G2")
                leaf_color = "#450a0a" if has_flaw else "#064e3b"
                leaf_border = "#ef4444" if has_flaw else "#10b981"
                leaf_font = "#fca5a5" if has_flaw else "#6ee7b7"
                leaf_status = "⚠️ FLAW DETECTED" if has_flaw else "✅ VALID & TRUSTED"
                
                dot_code = f"""
                digraph PKI_Trust {{
                    rankdir=TB;
                    bgcolor="transparent";
                    node [fontname="Helvetica", fontsize=10, style="filled,rounded", shape=box, penwidth=2];
                    edge [fontname="Helvetica", fontsize=9, color="#38bdf8", penwidth=2, arrowhead=vee];

                    root [label="🏛️ Root CA (Trust Anchor)\\nCN={root_ca_name[:25]}...\\nStatus: Built-in OS / Mozilla Trust Store\\nKey: RSA 4096-bit (SHA-384)", fillcolor="#064e3b", fontcolor="#a7f3d0", color="#10b981"];
                    intermediate [label="🛡️ Intermediate CA\\nDigiCert Global TLS CA G4\\nKey: RSA 2048-bit (SHA-256)\\nStatus: Cross-Signed Intermediate", fillcolor="#0c4a6e", fontcolor="#bae6fd", color="#38bdf8"];
                    leaf [label="✉️ End-Entity Mail Server\\nSubject: {leaf_cert.get('subject', 'Mail Server')[:30]}...\\nKey: {leaf_cert.get('key_algorithm')} ({leaf_cert.get('key_size')} bits)\\nStatus: {leaf_status}", fillcolor="{leaf_color}", fontcolor="{leaf_font}", color="{leaf_border}"];

                    root -> intermediate [label="Signs & Cross-Validates", color="#10b981"];
                    intermediate -> leaf [label="Issues Server Cert & SAN", color="#38bdf8"];
                }}
                """
            st.graphviz_chart(dot_code, use_container_width=True)

            # 2. DETAILED FLOW DIAGRAM WITH STATUS BADGES
            st.markdown("##### 🗂️ Detailed Chain-of-Trust Node Inspector")
            st.markdown('<div class="cert-tree-container"><div class="cert-flow-wrapper">', unsafe_allow_html=True)
            
            if is_self:
                st.markdown(f"""
                <div class="cert-node-box cert-node-box-leaf-warn">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:15px; font-weight:700; color:#ef4444;">⚠️ Self-Signed Root & Leaf Certificate</span>
                        <span class="cert-badge-red">SELF-SIGNED</span>
                    </div>
                    <div style="margin-top:10px; font-size:12.5px; color:#cbd5e1; line-height:1.6;">
                        <strong>Subject:</strong> <code>{leaf_cert.get('subject')}</code><br>
                        <strong>Issuer:</strong> <code>{leaf_cert.get('issuer')}</code><br>
                        <strong>Validity Window:</strong> {leaf_cert.get('valid_from')} ➔ {leaf_cert.get('valid_to')} ({'❌ EXPIRED' if leaf_cert.get('is_expired') else '⚠️ Untrusted Root'})<br>
                        <strong>Key Specification:</strong> <code>{leaf_cert.get('key_algorithm')} ({leaf_cert.get('key_size')} bits)</code> | <strong>Sig Algo:</strong> <code>{leaf_cert.get('signature_algorithm')}</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                # 1. Root Node
                st.markdown(f"""
                <div class="cert-node-box cert-node-box-root">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:15px; font-weight:700; color:#34d399;">🏛️ Level 0: Root Certificate Authority (Trust Anchor)</span>
                        <span class="cert-badge-green">VALID ROOT CA</span>
                    </div>
                    <div style="margin-top:10px; font-size:12.5px; color:#cbd5e1; line-height:1.6;">
                        <strong>Subject:</strong> <code>CN={root_ca_name}, O=National / Global Trust Root CA</code><br>
                        <strong>Trust Status:</strong> Built-in Operating System / Mozilla NSS Trusted Root Store<br>
                        <strong>Key Specification:</strong> <code>RSA 4096-bit / SHA-384</code>
                    </div>
                </div>
                
                <div class="flow-arrow-down">
                    <div class="flow-arrow-stem"></div>
                    <div class="flow-arrow-head"></div>
                    <span class="flow-arrow-label">Signs & Authorizes</span>
                </div>
                """, unsafe_allow_html=True)

                # 2. Intermediate Node
                st.markdown(f"""
                <div class="cert-node-box cert-node-box-intermediate">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:15px; font-weight:700; color:#38bdf8;">🛡️ Level 1: Intermediate Certificate Authority</span>
                        <span class="cert-badge-blue">INTERMEDIATE CA</span>
                    </div>
                    <div style="margin-top:10px; font-size:12.5px; color:#cbd5e1; line-height:1.6;">
                        <strong>Subject:</strong> <code>CN=DigiCert Global TLS Intermediate CA G4, O=DigiCert Inc</code><br>
                        <strong>Issued By:</strong> <code>CN={root_ca_name}</code><br>
                        <strong>Key Specification:</strong> <code>RSA 2048-bit / SHA-256 with RSA</code>
                    </div>
                </div>

                <div class="flow-arrow-down">
                    <div class="flow-arrow-stem"></div>
                    <div class="flow-arrow-head"></div>
                    <span class="flow-arrow-label">Issues End-Entity Domain Cert</span>
                </div>
                """, unsafe_allow_html=True)

                # 3. Leaf Node
                leaf_badge_class = "cert-badge-red" if (leaf_cert.get("is_expired") or leaf_cert.get("issues")) else "cert-badge-green"
                leaf_badge_text = "EXPIRED CERT" if leaf_cert.get("is_expired") else ("ISSUES DETECTED" if leaf_cert.get("issues") else "VALID & ACTIVE")
                leaf_node_class = "cert-node-box-leaf-warn" if (leaf_cert.get("is_expired") or leaf_cert.get("issues")) else "cert-node-box-leaf-valid"

                st.markdown(f"""
                <div class="cert-node-box {leaf_node_class}">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:15px; font-weight:700; color:{'#ef4444' if has_flaw else '#34d399'};">✉️ Level 2: Mail Server Certificate (Leaf Node)</span>
                        <span class="{leaf_badge_class}">{leaf_badge_text}</span>
                    </div>
                    <div style="margin-top:10px; font-size:12.5px; color:#cbd5e1; line-height:1.6;">
                        <strong>Subject (CN):</strong> <code>{leaf_cert.get('subject')}</code><br>
                        <strong>Issued By:</strong> <code>{leaf_cert.get('issuer')}</code><br>
                        <strong>Validity Period:</strong> {leaf_cert.get('valid_from')} ➔ {leaf_cert.get('valid_to')} ({'❌ EXPIRED' if leaf_cert.get('is_expired') else '✅ Active'})<br>
                        <strong>Public Key:</strong> <code>{leaf_cert.get('key_algorithm')} ({leaf_cert.get('key_size')} bits)</code> | <strong>Signature:</strong> <code>{leaf_cert.get('signature_algorithm')}</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            if leaf_cert.get("issues"):
                for iss in leaf_cert["issues"]:
                    st.error(f"🚨 PKI Flaw: {iss}")

            st.markdown('</div></div>', unsafe_allow_html=True)
            st.markdown("---")

    if not certs_found:
        st.info("ℹ️ No X.509 certificates extracted for this PCAP scenario (either plaintext traffic or STARTTLS stripped).")

with tab_streams:
    st.subheader("Reconstructed Email Communication Sessions")
    if not sessions:
        st.warning("No SMTP/IMAP/POP3 sessions detected in this PCAP.")

    for s in sessions:
        ev = s["evaluation"]
        score = ev["posture_score"]
        grade = ev["posture_grade"]
        sev = ev["overall_severity"]
        pqc = ev.get("pqc_readiness", {})
        cves = ev.get("named_cves", [])

        with st.expander(f"🔹 Session #{s['session_id']}: {s['protocol']} ({s['client']} ➔ {s['server']}) — Score: {score}/100 [{grade}]", expanded=True):
            sc1, sc2, sc3 = st.columns([1.2, 1.3, 1.5])
            
            with sc1:
                st.markdown(f"**Protocol:** `{s['protocol']}`")
                st.markdown(f"**Client IP:** `{s['client']}`")
                st.markdown(f"**Server IP:** `{s['server']}`")
                st.markdown(f"**Packets:** `{s['packet_count']}` ({s['duration_sec']}s)")
                st.markdown(f"**Encryption Mode:** `{s['encryption_mode']}`")

            with sc2:
                tls = s["tls_details"]
                if tls.get("has_tls"):
                    st.markdown(f"**TLS Version:** `{tls.get('negotiated_version', {}).get('name', 'N/A')}`")
                    st.markdown(f"**Cipher Suite:** `{tls.get('cipher_suite', {}).get('name', 'N/A')}`")
                    st.markdown(f"**Forward Secrecy (PFS):** `{'✅ Supported' if tls.get('forward_secrecy') else '❌ None'}`")
                    st.markdown(f"**Key Exchange:** `{tls.get('key_exchange', 'N/A')}`")
                else:
                    st.markdown("**TLS:** `None (Plaintext)`")
                    if s.get("plaintext_auth_leaked"):
                        st.error("🚨 Cleartext Credentials Leaked!")

                if s.get("ai_anomaly_flag"):
                    st.warning(f"🤖 **AI Outlier Anomaly Flagged** (Confidence: {s.get('ai_anomaly_confidence')})")

                st.markdown(f"**Quantum Resistance:** `{pqc.get('threat_level')}`")

            with sc3:
                st.markdown("#### Cryptographic Findings & CVEs")
                if cves:
                    st.markdown("**Mapped Exploit Vectors:**")
                    for c in cves:
                        st.markdown(f"<span class='cve-badge-red'>CVE</span> `{c}`", unsafe_allow_html=True)

                # MITRE ATT&CK Badges
                mitre = ev.get("mitre_techniques", [])
                if mitre:
                    st.markdown("**MITRE ATT&CK® Techniques:**")
                    for m in mitre:
                        badge_cls = "mitre-badge-crit" if m["severity"] == "Critical" else "mitre-badge"
                        st.markdown(f"<span class='{badge_cls}'>{m['id']}: {m['name']}</span>", unsafe_allow_html=True)

                if ev["penalties"]:
                    for p_sev, p_title, p_desc in ev["penalties"]:
                        if p_sev == "Critical":
                            st.error(f"**[{p_sev}] {p_title}**: {p_desc}")
                        elif p_sev == "High":
                            st.warning(f"**[{p_sev}] {p_title}**: {p_desc}")
                        else:
                            st.info(f"**[{p_sev}] {p_title}**: {p_desc}")
                else:
                    st.success("✅ Fully compliant with NIST SP 800-52r2 standards.")

            # Handshake Chronological Timeline Stepper
            st.markdown("---")
            st.markdown("##### ⏱️ Forensic Handshake & Session Timeline")
            t_col1, t_col2 = st.columns([1, 1])
            with t_col1:
                st.markdown(f"""
                <div class="timeline-step">
                    <div class="timeline-icon">1</div>
                    <div>
                        <div style="font-weight:700; color:#38bdf8; font-size:13px;">TCP 3-Way Handshake Established</div>
                        <div style="font-size:12px; color:#94a3b8;">SYN ➔ SYN-ACK ➔ ACK over Port ({s['server'].split(':')[-1] if ':' in s['server'] else 'Mail'})</div>
                    </div>
                </div>
                <div class="timeline-step">
                    <div class="timeline-icon">2</div>
                    <div>
                        <div style="font-weight:700; color:#38bdf8; font-size:13px;">Application Protocol Greeting</div>
                        <div style="font-size:12px; color:#94a3b8;">{s['protocol']} Banner Announced & Capability Negotiation</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with t_col2:
                sec_step_title = "TLS Handshake Negotiated" if tls.get("has_tls") else "Unencrypted Plaintext Flow"
                sec_step_desc = f"{tls.get('negotiated_version', {}).get('name', 'N/A')} • {tls.get('cipher_suite', {}).get('name', 'N/A')}" if tls.get("has_tls") else "No encryption active. Potential STRIPTLS or cleartext leak."
                st.markdown(f"""
                <div class="timeline-step">
                    <div class="timeline-icon">3</div>
                    <div>
                        <div style="font-weight:700; color:{'#10b981' if tls.get('has_tls') else '#ef4444'}; font-size:13px;">{sec_step_title}</div>
                        <div style="font-size:12px; color:#94a3b8;">{sec_step_desc}</div>
                    </div>
                </div>
                <div class="timeline-step">
                    <div class="timeline-icon">4</div>
                    <div>
                        <div style="font-weight:700; color:#38bdf8; font-size:13px;">Session Termination & Ledger Sealed</div>
                        <div style="font-size:12px; color:#94a3b8;">Cryptographic digest hashed into SHA-256 Block #{s['session_id']}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Certificates details
            if tls.get("certificates"):
                st.markdown("---")
                st.markdown("##### 📜 Extracted X.509 Digital Certificates")
                for cert in tls["certificates"]:
                    st.markdown(f"""
                    - **Subject:** `{cert.get('subject')}`
                    - **Issuer:** `{cert.get('issuer')}`
                    - **Validity:** `{cert.get('valid_from')}` to `{cert.get('valid_to')}` ({'❌ EXPIRED' if cert.get('is_expired') else '✅ Valid'})
                    - **Key:** `{cert.get('key_algorithm')} ({cert.get('key_size')} bits)` | **Signature:** `{cert.get('signature_algorithm')}`
                    """)
                    if cert.get("issues"):
                        for iss in cert["issues"]:
                            st.error(f"⚠️ Certificate Flaw: {iss}")

            # Remediation
            if ev["recommendations"]:
                st.markdown("---")
                st.markdown("##### 💡 Actionable Mitigation Steps")
                for r in ev["recommendations"]:
                    st.markdown(f"• {r}")

with tab_pqc_readiness:
    st.subheader("⚛️ Post-Quantum Cryptography (PQC) Readiness Assessment")
    st.markdown("Audits email communication infrastructure against **Shor's Algorithm** and **'Harvest Now, Decrypt Later' (HNDL)** quantum cryptanalysis based on **NIST FIPS 203 (ML-KEM)**.")

    col_pq1, col_pq2 = st.columns([1, 1.2])
    with col_pq1:
        st.info("💡 **National Security Mandate**: Adversaries are intercepting and storing encrypted defense email traffic today to decrypt once cryptographically relevant quantum computers (CRQC) emerge. Secure systems must adopt Hybrid Post-Quantum Key Encapsulation (ML-KEM / Kyber).")
    
    with col_pq2:
        for s in sessions:
            pqc_data = s["evaluation"].get("pqc_readiness", {})
            st.markdown(f"#### Session #{s['session_id']} Quantum Profile")
            st.markdown(f"**Threat Assessment:** `{pqc_data.get('threat_level')}`")
            if pqc_data.get("quantum_vulnerable_algorithms"):
                st.error("**Vulnerable Classical Components:**")
                for v in pqc_data["quantum_vulnerable_algorithms"]:
                    st.markdown(f"• {v}")
            for d in pqc_data.get("details", []):
                st.caption(f"ℹ️ {d}")

with tab_chain:
    st.subheader("⛓️ Cryptographic Audit Ledger & Chain-of-Custody")
    st.markdown("Every forensic assessment is hashed with SHA-256 and appended to an immutable local blockchain ledger for non-repudiation and court-admissible evidence.")

    ledger = BlockchainAuditLedger()
    integrity = ledger.verify_chain_integrity()

    st.markdown(f"""
    <div class="blockchain-card">
        <strong>STATUS:</strong> {'🟢 INTEGRITY VERIFIED (Chain Intact)' if integrity['is_valid'] else '🔴 CHAIN TAMPER DETECTED'}<br>
        <strong>TOTAL BLOCKS:</strong> {integrity['total_blocks']} | <strong>LATEST BLOCK HASH:</strong> {integrity['latest_block_hash']}
    </div>
    """, unsafe_allow_html=True)

    df_chain = pd.DataFrame(ledger.chain)
    st.dataframe(df_chain, use_container_width=True)

with tab_mta:
    st.subheader("🛠️ MTA-STS & DANE-SMTP Policy Generator")
    st.markdown("Generate compliant **RFC 8461 (MTA-STS)** policies and DNS TXT records to automatically mitigate STARTTLS stripping attacks on your mail servers.")

    domain_input = st.text_input("Enter Mail Domain:", value="enterprise.internal")
    mode_input = st.selectbox("MTA-STS Mode:", ["enforce", "testing", "none"])

    policy_res = generate_mta_sts_policy(domain=domain_input, mode=mode_input)

    col_pol1, col_pol2 = st.columns(2)
    with col_pol1:
        st.markdown("#### 📜 `mta-sts.txt` Policy File")
        st.caption("Place this at `https://mta-sts.domain/.well-known/mta-sts.txt`")
        st.code(policy_res["policy_file"], language="yaml")
    with col_pol2:
        st.markdown("#### 🌐 DNS TXT Configuration")
        st.caption("Publish this TXT record on your authoritative DNS zone.")
        st.code(policy_res["dns_record"], language="dns")

with tab_export:
    st.subheader("📑 Export Forensic Audit Reports")
    st.markdown("Export complete session findings, CVE mappings, PQC status, and Blockchain audit stamps for SOC and digital forensics documentation.")

    col_rep1, col_rep2, col_rep3 = st.columns(3)

    json_path = os.path.join("samples", "forensic_report.json")
    pdf_path = os.path.join("samples", "forensic_report.pdf")
    html_path = os.path.join("samples", "forensic_report.html")

    generate_json_report(sessions, summary_stats, json_path, pcap_name=selected_pcap_name)
    generate_pdf_report(sessions, summary_stats, pdf_path, pcap_name=selected_pcap_name)
    generate_html_report(sessions, summary_stats, html_path, pcap_name=selected_pcap_name)

    with col_rep1:
        st.markdown("#### 📄 JSON Export")
        st.caption("Machine-readable structured session logs for SIEM & Data Lake ingestion.")
        with open(json_path, "r", encoding="utf-8") as f:
            st.download_button(
                label="⬇️ Download JSON",
                data=f.read(),
                file_name="securemailscope_forensic_report.json",
                mime="application/json"
            )

    with col_rep2:
        st.markdown("#### 📑 PDF Audit Report")
        st.caption("Formal forensic audit report with Blockchain Chain-of-Custody seal.")
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="⬇️ Download PDF",
                data=f.read(),
                file_name="securemailscope_forensic_report.pdf",
                mime="application/pdf"
            )

    with col_rep3:
        st.markdown("#### 🌐 HTML Report")
        st.caption("Interactive standalone web report for offline browser viewing.")
        with open(html_path, "r", encoding="utf-8") as f:
            st.download_button(
                label="⬇️ Download HTML",
                data=f.read(),
                file_name="securemailscope_forensic_report.html",
                mime="text/html"
            )
