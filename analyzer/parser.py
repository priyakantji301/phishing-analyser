import hashlib
from email import policy
from email.parser import BytesParser

def parse_eml(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    html_part = msg.get_body(("html",))
    text_part = msg.get_body(("plain",))

    attachments = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": part.get_filename() or "(unnamed)",
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })

    return {
        "from": msg["From"],
        "reply_to": msg["Reply-To"],
        "return_path": msg["Return-Path"],
        "subject": msg["Subject"],
        "auth": msg["Authentication-Results"],
        "html": html_part.get_content() if html_part else "",
        "text": text_part.get_content() if text_part else "",
        "attachments": attachments,
    }

if __name__ == "__main__":
    import sys, pprint
    pprint.pprint(parse_eml(sys.argv[1]))
