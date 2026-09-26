import glob
from analyzer import MailStreamAnalyzer
from evaluator import CryptographicEvaluator
from reporter import generate_json_report, generate_pdf_report, generate_html_report

def main():
    pcap_files = glob.glob("samples/*.pcap")
    print(f"Found {len(pcap_files)} PCAP files to test.\n")
    
    for p in pcap_files:
        print(f"--- Testing {p} ---")
        analyzer = MailStreamAnalyzer(p)
        sessions, stats = analyzer.parse()
        evaluator = CryptographicEvaluator()
        for s in sessions:
            s["evaluation"] = evaluator.evaluate_session(s)
            ev = s["evaluation"]
            print(f"  [+] Session #{s['session_id']}: {s['protocol']} ({s['client']} -> {s['server']})")
            print(f"      Mode: {s['encryption_mode']} | Posture Score: {ev['posture_score']}/100 [{ev['posture_grade']}]")
            if s.get("plaintext_auth_leaked"):
                print(f"      🚨 AUTH Leak: {s['plaintext_auth_leaked']}")
            if s['tls_details'].get('has_tls'):
                tls = s['tls_details']
                ver = tls.get('negotiated_version', {}).get('name', 'N/A')
                ciph = tls.get('cipher_suite', {}).get('name', 'N/A')
                print(f"      TLS: {ver} | Cipher: {ciph}")
        print()

    print("Generating test forensic JSON, PDF, and HTML reports...")
    generate_json_report(sessions, stats, "samples/test_report.json")
    generate_pdf_report(sessions, stats, "samples/test_report.pdf")
    generate_html_report(sessions, stats, "samples/test_report.html")
    print("✅ Full pipeline verification succeeded! JSON, PDF, and HTML reports created.")

if __name__ == "__main__":
    main()
