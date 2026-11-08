import re

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

def check_domain_mismatch(from_, reply_to, return_path):
    """Flag if From, Reply-To and Return-Path domains differ."""
    # TODO: use get_domain on each, compare them
    pass

def check_display_name(from_):
    """Flag if the display name claims a brand the domain doesn't match."""
    # TODO: a small dict like {"paypal": "paypal.com", ...}
    pass

def run_auth_checks(data):
    """Run everything on the dict returned by parse_eml."""
    # TODO: combine all results into one list
    pass
