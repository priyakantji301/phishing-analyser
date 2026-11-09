import re
from html import unescape

# category -> (points, label, trigger phrases). Each category counts ONCE per email.
CATEGORIES = {
    "urgency": (10, "Urgent or pressuring wording", [
        "urgent", "immediately", "act now", "right away", "within 24 hours",
        "within 48 hours", "expires today", "last warning", "final notice"]),
    "threat": (10, "Threatening wording", [
        "account will be suspended", "account suspended", "account has been locked",
        "account locked", "unusual activity", "suspicious activity",
        "will be closed", "will be terminated", "legal action"]),
    "credential_request": (20, "Asks you to verify or enter credentials", [
        "verify your account", "verify your identity", "confirm your password",
        "confirm your identity", "update your payment", "update your billing",
        "enter your password", "log in to verify", "validate your account"]),
    "generic_greeting": (5, "Generic greeting", [
        "dear customer", "dear user", "dear valued", "dear sir",
        "dear account holder", "dear member", "dear client"]),
    "lure": (10, "Reward or windfall lure", [
        "you have won", "you've won", "claim your prize", "claim your reward",
        "gift card", "free gift", "lottery", "inheritance"]),
}


def html_to_text(html):
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html or "")
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def finding(check, points, detail):
    return {"check": check, "result": "suspicious", "points": points, "detail": detail}


def run_content_checks(data):
    subject = str(data["subject"] or "")
    body = (data.get("text") or "") + " " + html_to_text(data["html"])
    full = (subject + " " + body).lower()
    findings = []

    # 1. Phrase categories
    for name, (points, label, phrases) in CATEGORIES.items():
        hits = [p for p in phrases if p in full]
        if hits:
            findings.append(finding(name, points, f"{label}: {', '.join(hits[:3])}"))

    # 2. Shouting subject
    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        findings.append(finding("shouting_subject", 5, "Subject is mostly capital letters"))

    # 3. Excessive exclamation marks
    if (subject + body).count("!") >= 3:
        findings.append(finding("exclamations", 5, "Excessive exclamation marks"))

    # 4. Password box inside the email itself
    if re.search(r"<input[^>]+type\s*=\s*[\"']?password", data["html"] or "", re.I):
        findings.append(finding("password_form", 25,
                                "Email contains a password input field"))

    return findings
