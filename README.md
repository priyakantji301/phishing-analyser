# Phishing Email Analyser

Parses .eml files and scores phishing risk using header authentication,
URL analysis, attachment hashing, and content heuristics.

## Usage
python3 main.py samples/fake/fake1.eml

## Status
- [x] Email parser
- [x] SPF/DKIM/DMARC checks
- [x] URL analysis
- [x] Attachment hashing
- [x] Risk scoring
- [x] Content heuristics
- [x] Web interface (run: uvicorn app:app --reload)
