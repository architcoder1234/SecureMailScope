import json
from pathlib import Path
from jinja2 import Environment, BaseLoader
from ..models.schemas import AnalysisReport

HTML_TEMPLATE = """
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SecureMailScope Report — {{ report.pcap_filename }}</title>
<style>
body { font-family: -apple-system, Arial, sans-serif; margin: 2rem; background: #0b0d12; color: #e6e6e6; }
h1 { color: #7dd3fc; } h2 { color: #a5b4fc; margin-top: 2rem; }
.summary { display:flex; gap:1rem; margin: 1rem 0 2rem; }
.badge { padding: 0.6rem 1rem; border-radius: 8px; font-weight: 600; }
.CRITICAL { background:#7f1d1d; color:#fecaca; }
.HIGH { background:#7c2d12; color:#fed7aa; }
.MEDIUM { background:#78350f; color:#fde68a; }
.LOW { background:#14532d; color:#bbf7d0; }
.session { border:1px solid #262b36; border-radius:10px; padding:1rem; margin-bottom:1rem; background:#11151c; }
.finding { padding:0.4rem 0.6rem; border-radius:6px; margin:0.3rem 0; font-size:0.9rem; }
table { border-collapse: collapse; width:100%; margin-top:0.5rem;}
td, th { border:1px solid #262b36; padding:0.4rem 0.6rem; text-align:left; font-size:0.85rem;}
</style></head>
<body>
<h1>SecureMailScope — Cryptographic Security Posture Report</h1>
<p>Source capture: <strong>{{ report.pcap_filename }}</strong> — {{ report.total_sessions }} email session(s) analyzed</p>
<div class="summary">
  <div class="badge CRITICAL">Critical: {{ report.summary.critical }}</div>
  <div class="badge HIGH">High: {{ report.summary.high }}</div>
  <div class="badge MEDIUM">Medium: {{ report.summary.medium }}</div>
  <div class="badge LOW">Low: {{ report.summary.low }}</div>
</div>

{% for s in report.sessions %}
<div class="session">
  <h2>{{ s.protocol }} — {{ s.client_ip }}:{{ s.client_port }} → {{ s.server_ip }}:{{ s.server_port }}
    <span class="badge {{ s.risk_label }}">{{ s.risk_label }} ({{ s.final_score }})</span>
  </h2>
  <p>TLS version: {{ s.tls_version or "N/A" }} | Cipher: {{ s.negotiated_cipher or "N/A" }} |
     Forward secrecy: {{ "Yes" if s.forward_secrecy else "No" }} | STARTTLS: {{ "Yes" if s.starttls_seen else "No" }}</p>

  {% for f in s.findings %}
  <div class="finding {{ f.severity }}">[{{ f.severity }}] {{ f.category }}: {{ f.detail }}</div>
  {% endfor %}

  {% if s.certificates %}
  <table>
    <tr><th>Subject</th><th>Issuer</th><th>Expiry</th><th>Key</th><th>Signature</th><th>Self-signed</th></tr>
    {% for c in s.certificates %}
    <tr>
      <td>{{ c.subject }}</td><td>{{ c.issuer }}</td>
      <td>{{ c.not_after }} ({{ c.days_until_expiry }}d)</td>
      <td>{{ c.public_key_type }} {{ c.public_key_size }}b</td>
      <td>{{ c.signature_algorithm }}</td>
      <td>{{ "Yes" if c.is_self_signed else "No" }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</div>
{% endfor %}
</body></html>
"""


def to_json(report: AnalysisReport, out_path: str):
    Path(out_path).write_text(json.dumps(report.model_dump(), indent=2))


def to_html(report: AnalysisReport, out_path: str):
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    Path(out_path).write_text(template.render(report=report))


def to_pdf(report: AnalysisReport, out_path: str):
    """Requires weasyprint + its system deps (pango/cairo). Renders HTML then converts."""
    from weasyprint import HTML
    env = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    html_str = template.render(report=report)
    HTML(string=html_str).write_pdf(out_path)
