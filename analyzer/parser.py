from email import policy
from email.parser import BytesParser

def parse_eml(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    html_part = msg.get_body(("html",))
    return {
        "from": msg["From"],
        "reply_to": msg["Reply-To"],
        "return_path": msg["Return-Path"],
        "subject": msg["Subject"],
        "auth": msg["Authentication-Results"],
        "html": html_part.get_content() if html_part else "",
        "attachments": [p.get_filename() for p in msg.iter_attachments()],
    }

if __name__ == "__main__":
    import sys, pprint
    pprint.pprint(parse_eml(sys.argv[1]))
