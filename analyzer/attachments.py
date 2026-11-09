RISKY_EXT = {
    ".exe": 30, ".scr": 30, ".bat": 30, ".cmd": 30, ".com": 30, ".msi": 30,
    ".js": 30, ".vbs": 30, ".ps1": 30, ".jar": 30, ".lnk": 30, ".hta": 30,
    ".iso": 30, ".img": 30, ".dll": 30,
    ".docm": 20, ".xlsm": 20, ".pptm": 20,
    ".html": 15, ".htm": 15,
    ".zip": 10, ".rar": 10, ".7z": 10, ".gz": 10,
}
EXECUTABLE_EXT = {e for e, p in RISKY_EXT.items() if p == 30}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png"}


def finding(check, result, points, detail):
    return {"check": check, "result": result, "points": points, "detail": detail}


def check_attachment(att):
    """Judge one attachment by name and type. Never opens the file."""
    name = att["filename"]
    lower = name.lower()
    parts = lower.split(".")
    ext = "." + parts[-1] if len(parts) > 1 else ""
    findings = []

    # 1. Risky file type
    if ext in RISKY_EXT:
        findings.append(finding("risky_attachment", "suspicious", RISKY_EXT[ext],
                                f"Risky attachment type {ext}: {name}"))

    # 2. Double extension like invoice.pdf.exe
    if len(parts) >= 3 and ext in EXECUTABLE_EXT and "." + parts[-2] in DOC_EXT:
        findings.append(finding("double_extension", "suspicious", 25,
                                f"Double extension disguises a program as a document: {name}"))

    # 3. Right-to-left override trick
    if "\u202e" in name:
        findings.append(finding("rlo_filename", "suspicious", 30,
                                f"Filename contains a hidden right-to-left override character: {name!r}"))

    # 4. Fingerprint for lookup (information only)
    findings.append(finding("attachment_hash", "info", 0,
                            f"{name} SHA-256: {att['sha256']}"))
    return findings


def run_attachment_checks(data):
    findings = []
    for att in data["attachments"]:
        findings += check_attachment(att)
    return findings
