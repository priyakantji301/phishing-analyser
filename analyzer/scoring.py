from analyzer.auth_checks import run_auth_checks
from analyzer.url_checks import run_url_checks
from analyzer.attachments import run_attachment_checks
from analyzer.heuristics import run_content_checks

MAX_PER_CATEGORY = 50      # one category alone can never contribute more than this
HIGH_AT = 70               # total needed for High
MEDIUM_AT = 30             # total needed for Medium
CRITICAL = {"password_form", "double_extension", "rlo_filename"}                 # force High
SERIOUS = {"link_text_mismatch", "lookalike_domain", "display_name_spoof"}       # force at least Medium
LEVELS = ["Low", "Medium", "High"]


def analyze(data):
    """Run every check, cap each category, and produce one explainable verdict."""
    runners = {
        "Authentication": run_auth_checks,
        "URLs": run_url_checks,
        "Attachments": run_attachment_checks,
        "Content": run_content_checks,
    }

    sections = {}
    all_findings = []
    total = 0
    for name, run in runners.items():
        findings = run(data)
        raw = sum(f["points"] for f in findings)
        score = min(raw, MAX_PER_CATEGORY)
        sections[name] = {"findings": findings, "raw": raw, "score": score}
        all_findings += findings
        total += score

    if total >= HIGH_AT:
        level = "High"
    elif total >= MEDIUM_AT:
        level = "Medium"
    else:
        level = "Low"

    # Severe findings can raise the verdict, never lower it
    checks = {f["check"] for f in all_findings}
    floor = "Low"
    if checks & CRITICAL:
        floor = "High"
    elif checks & SERIOUS:
        floor = "Medium"

    override_note = None
    if LEVELS.index(floor) > LEVELS.index(level):
        triggers = ", ".join(sorted(checks & (CRITICAL | SERIOUS)))
        override_note = f"Raised to {floor} because of a severe finding: {triggers}"
        level = floor

    top = sorted((f for f in all_findings if f["points"] > 0),
                 key=lambda f: f["points"], reverse=True)[:3]

    return {
        "subject": data["subject"],
        "from": data["from"],
        "verdict": level,
        "total": total,
        "sections": sections,
        "top_reasons": top,
        "override_note": override_note,
    }
