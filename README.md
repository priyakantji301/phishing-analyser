# Phishing Email Analyser

A Python tool that reads a suspicious email (`.eml`) and returns a **Low / Medium / High risk verdict with the reasons behind it**. It runs as a command-line tool, a web app, or a JSON API.

Built for safe analysis: emails are processed in memory, links are never visited, and attachments are never opened.

<!-- screenshots -->

## What it checks

| Area | Examples |
|---|---|
| **Sender** | SPF, DKIM and DMARC results; From vs Reply-To vs Return-Path domains; display names that impersonate a brand |
| **Links** | Link text that hides the real destination, lookalike domains (`paypa1.com`), raw IPs, URL shorteners, punycode, plain `http` |
| **Attachments** | Risky file types, macro-enabled Office files, double extensions (`invoice.pdf.exe`), SHA-256 fingerprint of each file |
| **Wording** | Urgency, threats, credential requests, reward lures, generic greetings, password boxes inside the email |

SPF, DKIM and DMARC are not re-run. The tool reads the verdicts the receiving mail server wrote into the `Authentication-Results` header.

## Quick start

Requires Python 3.9+.

```bash
git clone https://github.com/priyakantji301/phishing-analyser.git
cd phishing-analyser
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

**Command line**

```bash
python3 main.py samples/fake/fake1.eml
```

**Web app**

```bash
uvicorn app:app --reload
```

Open <http://127.0.0.1:8000> and upload an `.eml` file.

**JSON API**

```bash
curl -s -F "file=@samples/fake/fake1.eml" http://127.0.0.1:8000/api/analyze
```

## How scoring works

Every check returns findings in one format (`check`, `result`, `points`, `detail`), so the scorer can combine them.

1. **Cap per area:** each of the four areas contributes at most 50 points, so one noisy area cannot decide alone.
2. **Thresholds:** 0 to 29 is Low, 30 to 69 is Medium, 70 and above is High.
3. **Overrides:** findings that legitimate email almost never produces raise the verdict. A password box or a double extension forces High. A link text mismatch, lookalike domain or brand impersonation forces at least Medium.
4. **Explainable:** the report shows the top three reasons first, and every point traces back to a finding.

Weights and thresholds are judgement calls and are easy to tune in `analyzer/`.

## Project structure

```
phishing-analyser/
├── analyzer/
│   ├── parser.py          # .eml bytes -> dictionary
│   ├── auth_checks.py     # SPF/DKIM/DMARC, domain mismatch, display name
│   ├── url_checks.py      # link extraction and analysis
│   ├── attachments.py     # file types and SHA-256
│   ├── heuristics.py      # wording and password-form checks
│   └── scoring.py         # caps, thresholds, overrides, verdict
├── templates/             # Jinja2 pages
├── static/                # CSS and JS
├── samples/
│   ├── fake/              # hand-written test emails (safe to commit)
│   └── real/              # real phishing samples (git-ignored)
├── tests/
├── app.py                 # web app and JSON API
├── main.py                # command line
└── requirements.txt
```

The parser only extracts facts. The checks only judge them. The CLI, web app and API all call the same `analyze()` function.

## Safety by design

- Links are never visited, and attachments are never opened or run.
- Uploads are analysed in memory and never saved (`.eml` only, 5 MB limit).
- All displayed values are auto-escaped, and the email's own HTML is never rendered.
- The server binds to `127.0.0.1` and the API docs page is disabled.
- `samples/real/` is git-ignored. Handle real phishing samples only inside a VM.

## Sample emails

| File | Demonstrates | Expected verdict |
|---|---|---|
| `fake1.eml` | Lookalike domain, mismatched Reply-To, failed authentication, misleading link | High (130) |
| `fake2.eml` | Disguised `.exe` and macro-enabled attachment | High (50, raised by override) |
| `fake3.eml` | Pressure wording and a password box | High (50, raised by override) |
| `forwarded1.eml` | Clean forwarded email that fails authentication | Medium (50) |
| `legit1.eml`, `legit2.eml` | Genuine emails | Low (0) |

## Limitations

- A pass on SPF, DKIM and DMARC does not prove an email is safe, because attackers can set them up on their own lookalike domains.
- Brand, shortener and phrase lists are short, hand-written and English-only.
- Attachment checks trust the filename, and archive contents are not inspected.
- Only `<a>` links are checked. Bare URLs, image links and QR codes are not.
- No automated tests yet, and no login, rate limiting or HTTPS, so run it locally.

## Roadmap

- [x] Parser, authentication, URL, attachment and wording checks
- [x] Scoring with explainable verdict
- [x] Web interface and JSON API
- [ ] Unit tests
- [ ] VirusTotal hash lookup and domain age (WHOIS)
- [ ] Detect real file type from file contents
- [ ] SIEM integration (Wazuh)
