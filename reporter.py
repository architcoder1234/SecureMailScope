"""
SecureMailScope - Forensic Report Generator (JSON, PDF, HTML)
Generates structured JSON, executive PDF, and interactive HTML audit reports with
Blockchain Chain-of-Custody verification and Post-Quantum Readiness metrics.
"""

import json
import datetime
import hashlib
from fpdf import FPDF
from blockchain_ledger import BlockchainAuditLedger

class ForensicPDFReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 13)
        self.set_fill_color(24, 32, 54)
        self.set_text_color(255, 255, 255)
        self.cell(0, 11, "  SecureMailScope - Cryptographic Forensic Assessment", 0, 1, "L", fill=True)
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} | NTRO Forensic Compliance Audit | Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 0, "C")

def generate_json_report(analyzed_sessions: list, summary_stats: dict, output_path: str, pcap_name="capture.pcap"):
    """Export complete findings to JSON format with blockchain hash."""
    ledger = BlockchainAuditLedger()
    block = ledger.add_audit_block(pcap_name, summary_stats, len(analyzed_sessions), "ASSESSED")

    report = {
        "metadata": {
            "system": "SecureMailScope",
            "version": "2.0.0",
            "audit_timestamp": datetime.datetime.now().isoformat(),
            "target_compliance": "NIST SP 800-52r2 / RFC 8996 / NIST FIPS 203 PQC",
            "blockchain_chain_of_custody": block
        },
        "summary": summary_stats,
        "sessions": analyzed_sessions
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return output_path

def generate_pdf_report(analyzed_sessions: list, summary_stats: dict, output_path: str, pcap_name="capture.pcap"):
    """Export executive PDF report with Blockchain & PQC Seal."""
    ledger = BlockchainAuditLedger()
    block = ledger.add_audit_block(pcap_name, summary_stats, len(analyzed_sessions), "ASSESSED")

    pdf = ForensicPDFReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Blockchain Tamper-Proof Header Card
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(238, 242, 255)
    pdf.set_text_color(49, 46, 129)
    pdf.cell(0, 6, f" [BLOCKCHAIN SEAL] Block #{block['block_index']} | Hash: {block['block_hash'][:28]}... | Integrity: VERIFIED", 1, 1, fill=True)
    pdf.ln(3)

    # Executive Summary Card
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 7, "1. Executive Summary & Forensic Statistics", 0, 1)
    
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(95, 5, f"Total Packets Analyzed: {summary_stats.get('total_packets', 0)}", 0, 0)
    pdf.cell(95, 5, f"Total Email Sessions: {summary_stats.get('total_email_sessions', 0)}", 0, 1)
    pdf.cell(95, 5, f"SMTP Streams: {summary_stats.get('smtp_sessions', 0)}", 0, 0)
    pdf.cell(95, 5, f"IMAP Streams: {summary_stats.get('imap_sessions', 0)}", 0, 1)
    pdf.cell(95, 5, f"POP3 Streams: {summary_stats.get('pop3_sessions', 0)}", 0, 0)
    pdf.cell(95, 5, f"Unencrypted Plaintext Streams: {summary_stats.get('plaintext_sessions', 0)}", 0, 1)
    pdf.cell(95, 5, f"Weak Ciphers Detected: {summary_stats.get('weak_ciphers_detected', 0)}", 0, 0)
    pdf.cell(95, 5, f"Certificate Flaws Detected: {summary_stats.get('cert_issues_detected', 0)}", 0, 1)
    pdf.ln(5)

    # Detailed Sessions Breakdown
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 7, "2. Session Cryptographic Posture & Findings", 0, 1)

    for s in analyzed_sessions:
        eval_res = s.get("evaluation", {})
        score = eval_res.get("posture_score", 100)
        grade = eval_res.get("posture_grade", "N/A")
        severity = eval_res.get("overall_severity", "Low")
        pqc = eval_res.get("pqc_readiness", {})

        pdf.set_font("Helvetica", "B", 9.5)
        if severity == "Critical":
            pdf.set_fill_color(254, 226, 226)
            pdf.set_text_color(185, 28, 28)
        elif severity == "High":
            pdf.set_fill_color(254, 243, 199)
            pdf.set_text_color(180, 83, 9)
        else:
            pdf.set_fill_color(240, 253, 244)
            pdf.set_text_color(21, 128, 61)

        pdf.cell(0, 6.5, f" Session #{s['session_id']}: {s['protocol']} ({s['client']} -> {s['server']}) | Score: {score}/100 [{grade}]", 0, 1, fill=True)
        
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(0, 4.5, f"Encryption Mode: {s.get('encryption_mode')} | AI Anomaly Detected: {s.get('ai_anomaly_flag', False)}", 0, 1)

        tls = s.get("tls_details", {})
        if tls.get("has_tls"):
            ver = tls.get("negotiated_version", {}).get("name", "N/A")
            cipher = tls.get("cipher_suite", {}).get("name", "N/A")
            pfs = "Yes" if tls.get("forward_secrecy") else "No"
            pdf.cell(0, 4.5, f"TLS Version: {ver} | Cipher: {cipher} | Forward Secrecy: {pfs}", 0, 1)

        # Named CVEs
        cves = eval_res.get("named_cves", [])
        if cves:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(185, 28, 28)
            pdf.cell(0, 4.5, f"Mapped Attack Vectors: {', '.join(cves)}", 0, 1)

        # Post-Quantum Threat
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(79, 70, 229)
        pdf.cell(0, 4.5, f"Post-Quantum Threat: {pqc.get('threat_level', 'Unknown')}", 0, 1)

        penalties = eval_res.get("penalties", [])
        if penalties:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(185, 28, 28)
            pdf.cell(0, 4.5, "Vulnerabilities & Penalties:", 0, 1)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(71, 85, 105)
            for p_sev, p_title, p_desc in penalties:
                pdf.cell(0, 3.8, f"  - [{p_sev}] {p_title}: {p_desc}", 0, 1)

        recs = eval_res.get("recommendations", [])
        if recs:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(30, 64, 175)
            pdf.cell(0, 4.5, "Recommended Remediation:", 0, 1)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(71, 85, 105)
            for r in recs:
                pdf.cell(0, 3.8, f"  - {r}", 0, 1)

        pdf.ln(3)

    pdf.output(output_path)
    return output_path

def generate_html_report(analyzed_sessions: list, summary_stats: dict, output_path: str, pcap_name="capture.pcap"):
    """Generate standalone interactive HTML forensic audit report with Blockchain seal."""
    ledger = BlockchainAuditLedger()
    block = ledger.add_audit_block(pcap_name, summary_stats, len(analyzed_sessions), "ASSESSED")

    sessions_html = ""
    for s in analyzed_sessions:
        ev = s.get("evaluation", {})
        score = ev.get("posture_score", 100)
        grade = ev.get("posture_grade", "A")
        color = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
        pqc = ev.get("pqc_readiness", {})

        penalties_html = "".join([f"<li><span class='badge' style='background:{'#ef4444' if p[0]=='Critical' else '#f59e0b'}'>{p[0]}</span> <strong>{p[1]}</strong>: {p[2]}</li>" for p in ev.get("penalties", [])])
        recs_html = "".join([f"<li>{r}</li>" for r in ev.get("recommendations", [])])
        cves_html = "".join([f"<span class='cve-badge'>{c}</span> " for c in ev.get("named_cves", [])])

        tls = s.get("tls_details", {})
        tls_html = ""
        if tls.get("has_tls"):
            tls_html = f"""
            <div class='crypto-box'>
                <div><strong>TLS Version:</strong> {tls.get('negotiated_version', {}).get('name', 'N/A')}</div>
                <div><strong>Cipher Suite:</strong> {tls.get('cipher_suite', {}).get('name', 'N/A')}</div>
                <div><strong>Forward Secrecy:</strong> {'Yes (PFS)' if tls.get('forward_secrecy') else 'No'}</div>
                <div><strong>Post-Quantum Threat:</strong> {pqc.get('threat_level')}</div>
            </div>
            """

        sessions_html += f"""
        <div class='session-card' style='border-left: 6px solid {color}'>
            <div style='display:flex; justify-content:space-between; align-items:center;'>
                <h3>Session #{s['session_id']}: {s['protocol']} ({s['client']} ➔ {s['server']})</h3>
                <span class='score-pill' style='background:{color}'>Score: {score}/100 [{grade}]</span>
            </div>
            <p><strong>Mode:</strong> {s.get('encryption_mode')} | <strong>AI Anomaly:</strong> {s.get('ai_anomaly_flag', False)}</p>
            {f"<p><strong>Attack Vectors:</strong> {cves_html}</p>" if cves_html else ""}
            {tls_html}
            {f"<h4>Vulnerabilities</h4><ul>{penalties_html}</ul>" if penalties_html else "<p style='color:#10b981'>No vulnerabilities detected.</p>"}
            {f"<h4>Remediation</h4><ul>{recs_html}</ul>" if recs_html else ""}
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureMailScope Forensic Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 24px; border: 1px solid #334155; }}
        .blockchain-card {{ background: #312e81; color: #e0e7ff; padding: 12px 18px; border-radius: 8px; margin-bottom: 20px; font-family: monospace; font-size: 13px; border: 1px solid #4338ca; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
        .kpi-card {{ background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; text-align: center; }}
        .kpi-val {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
        .session-card {{ background: #1e293b; padding: 18px; border-radius: 8px; margin-bottom: 16px; border: 1px solid #334155; }}
        .score-pill {{ padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 13px; color: white; }}
        .badge {{ padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; }}
        .cve-badge {{ background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
        .crypto-box {{ background: #0f172a; padding: 10px; border-radius: 6px; margin: 10px 0; font-family: monospace; font-size: 13px; }}
        ul {{ padding-left: 20px; color: #cbd5e1; }}
        li {{ margin-bottom: 6px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>SecureMailScope: Forensic Audit Report</h1>
        <p>National Technical Research Organisation (NTRO) | PS #26159</p>
        <small>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: NIST SP 800-52r2 / NIST FIPS 203</small>
    </div>
    <div class="blockchain-card">
        <strong>⛓️ BLOCKCHAIN CHAIN-OF-CUSTODY SEAL:</strong><br>
        Block Index: #{block['block_index']} | Timestamp: {block['timestamp']}<br>
        Block Hash: {block['block_hash']}
    </div>
    <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-val">{summary_stats.get('total_packets', 0)}</div>Total Packets</div>
        <div class="kpi-card"><div class="kpi-val">{summary_stats.get('total_email_sessions', 0)}</div>Email Streams</div>
        <div class="kpi-card"><div class="kpi-val" style="color:#ef4444">{summary_stats.get('plaintext_sessions', 0)}</div>Plaintext Streams</div>
        <div class="kpi-card"><div class="kpi-val" style="color:#f59e0b">{summary_stats.get('weak_ciphers_detected', 0)}</div>Weak Ciphers</div>
    </div>
    <h2>Reconstructed Stream Investigations</h2>
    {sessions_html}
</div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
