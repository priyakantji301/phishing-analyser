import sys
from analyzer.parser import parse_eml
from analyzer.auth_checks import run_auth_checks
from analyzer.url_checks import run_url_checks
from analyzer.attachments import run_attachment_checks

def show(title, findings):
    print(f"{title}:")
    if not findings:
        print("  (nothing found)")
    for f in findings:
        marker = "!" if f["points"] > 0 else " "
        print(f"  [{marker}] {f['detail']}  (+{f['points']})")
    print()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path-to-email.eml>")
        sys.exit(1)

    data = parse_eml(sys.argv[1])
    auth = run_auth_checks(data)
    urls = run_url_checks(data)
    atts = run_attachment_checks(data)

    print(f"\nSubject: {data['subject']}")
    print(f"From:    {data['from']}\n")
    show("Authentication", auth)
    show("URLs", urls)
    show("Attachments", atts)
    total = sum(f["points"] for f in auth + urls + atts)
    print(f"Total risk points: {total}")

if __name__ == "__main__":
    main()
