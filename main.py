import sys
from analyzer.parser import parse_eml
from analyzer.scoring import analyze

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path-to-email.eml>")
        sys.exit(1)

    r = analyze(parse_eml(sys.argv[1]))

    print(f"\nSubject: {r['subject']}")
    print(f"From:    {r['from']}\n")

    for name, sec in r["sections"].items():
        print(f"{name}  ({sec['score']} pts, raw {sec['raw']})")
        if not sec["findings"]:
            print("  (nothing found)")
        for f in sec["findings"]:
            marker = "!" if f["points"] > 0 else " "
            print(f"  [{marker}] {f['detail']}  (+{f['points']})")
        print()

    print(f"VERDICT: {r['verdict'].upper()}  ({r['total']} points)")
    if r["override_note"]:
        print(f"Note: {r['override_note']}")
    if r["top_reasons"]:
        print("\nTop reasons:")
        for i, f in enumerate(r["top_reasons"], 1):
            print(f"  {i}. {f['detail']} (+{f['points']})")

if __name__ == "__main__":
    main()
