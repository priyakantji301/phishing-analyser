import sys
from analyzer.parser import parse_eml
from analyzer.auth_checks import run_auth_checks

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path-to-email.eml>")
        sys.exit(1)

    data = parse_eml(sys.argv[1])
    findings = run_auth_checks(data)
    total = sum(f["points"] for f in findings)

    print(f"\nSubject: {data['subject']}")
    print(f"From:    {data['from']}\n")
    print("Findings:")
    for f in findings:
        marker = "!" if f["points"] > 0 else " "
        print(f"  [{marker}] {f['detail']}  (+{f['points']})")
    print(f"\nAuthentication risk points: {total}")

if __name__ == "__main__":
    main()
