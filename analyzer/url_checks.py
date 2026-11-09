import re
from html.parser import HTMLParser
from urllib.parse import urlparse
from analyzer.auth_checks import BRANDS, domains_match

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
              "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
LOOKALIKE_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


class LinkExtractor(HTMLParser):
    """Collects (text, href) for every <a> tag."""
    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"text": "".join(self._text).strip(), "href": self._href})
            self._href = None


def extract_links(html):
    parser = LinkExtractor()
    parser.feed(html or "")
    return parser.links


def get_host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def finding(check, points, detail):
    return {"check": check, "result": "suspicious", "points": points, "detail": detail}


def check_link(link):
    """Run all URL checks on one link and return a list of findings."""
    href, text = link["href"], link["text"]
    host = get_host(href)
    if not host:                      # mailto:, relative links, etc.
        return []
    findings = []

    # 1. Link text shows one domain, href goes to another
    m = re.search(r"([a-z0-9-]+(?:\.[a-z0-9-]+)+)", text.lower())
    if m and not domains_match(m.group(1), host):
        findings.append(finding("link_text_mismatch", 25,
                                f'Link text shows "{m.group(1)}" but goes to {host}'))

    # 2. Raw IP address instead of a domain name
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append(finding("ip_url", 20, f"Link uses a raw IP address: {host}"))

    # 3. URL shortener hides the real destination
    if host in SHORTENERS:
        findings.append(finding("shortener", 10, f"URL shortener hides destination: {host}"))

    # 4. Lookalike of a known brand (paypa1 -> paypal)
    normalized = host.translate(LOOKALIKE_MAP)
    for brand, legit_domains in BRANDS.items():
        if brand in normalized and not any(domains_match(host, d) for d in legit_domains):
            findings.append(finding("lookalike_domain", 20,
                                    f"{host} imitates {brand} but is not a {brand} domain"))
            break

    # 5. Punycode (xn--) can disguise lookalike characters
    if "xn--" in host:
        findings.append(finding("punycode", 15, f"Punycode domain (possible disguised characters): {host}"))

    # 6. Plain http, no encryption
    if urlparse(href).scheme == "http":
        findings.append(finding("insecure_http", 5, f"Link uses http, not https: {href}"))

    return findings


def run_url_checks(data):
    findings = []
    for link in extract_links(data["html"]):
        findings += check_link(link)
    return findings
