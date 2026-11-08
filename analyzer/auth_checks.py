import re
from email.utils import parseaddr

BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "microsoft": ["microsoft.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net"],
}

def check_auth_results(auth_header):
    """Read spf/dkim/dmarc verdicts from the Authentication-Results header."""
    points_map = {"pass": 0, "fail": 20, "softfail": 10, "none": 10, "neutral": 5}
    results = []
    for name in ("spf", "dkim", "dmarc"):
        verdict = "missing"
        if auth_header:
            match = re.search(rf"{name}=(\w+)", str(auth_header), re.IGNORECASE)
            if match:
                verdict = match.group(1).lower()
        results.append({
            "check": name,
            "result": verdict,
            "points": points_map.get(verdict, 10),
            "detail": f"{name.upper()} verdict: {verdict}",
        })
    return results

def get_domain(address):
    """Extract the domain from something like '"Name" <a@b.com>'."""
    if not address:
        return None
    match = re.search(r"@([\w.-]+)", str(address))
    if match:
        return match.group(1).lower()
    return None

def domains_match(a, b):
    """True if two domains are the same, or one is a subdomain of the other."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)

def check_domain_mismatch(from_, reply_to, return_path):
    """Flag if From, Reply-To and Return-Path domains differ."""
    from_d = get_domain(from_)
    reply_d = get_domain(reply_to)
    ret_d = get_domain(return_path)
    results = []

    if from_d and reply_d and not domains_match(from_d, reply_d):
        results.append({
            "check": "reply_to_mismatch",
            "result": "mismatch",
            "points": 20,
            "detail": f"From domain {from_d} differs from Reply-To domain {reply_d}",
        })

    if from_d and ret_d and not domains_match(from_d, ret_d):
        results.append({
            "check": "return_path_mismatch",
            "result": "mismatch",
            "points": 10,
            "detail": f"From domain {from_d} differs from Return-Path domain {ret_d}",
        })

    return results

def check_display_name(from_):
    """Flag if the display name claims a brand the sending domain doesn't match."""
    if not from_:
        return []
    display_name, address = parseaddr(str(from_))
    domain = get_domain(address)
    if not display_name or not domain:
        return []

    name_lower = display_name.lower()
    for brand, legit_domains in BRANDS.items():
        if re.search(rf"\b{brand}\b", name_lower):
            if not any(domains_match(domain, d) for d in legit_domains):
                return [{
                    "check": "display_name_spoof",
                    "result": "spoof",
                    "points": 25,
                    "detail": f'Display name "{display_name}" claims {brand}, but sent from {domain}',
                }]
    return []

def run_auth_checks(data):
    """Run every authentication check on the dict returned by parse_eml."""
    findings = []
    findings += check_auth_results(data["auth"])
    findings += check_domain_mismatch(data["from"], data["reply_to"], data["return_path"])
    findings += check_display_name(data["from"])
    return findings
