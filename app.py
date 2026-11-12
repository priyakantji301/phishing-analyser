from html import escape

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse

from analyzer.parser import parse_eml_bytes
from analyzer.scoring import analyze

MAX_BYTES = 5 * 1024 * 1024  # 5 MB upload limit
COLORS = {"High": "#c62828", "Medium": "#ef6c00", "Low": "#2e7d32"}

app = FastAPI(title="Phishing Email Analyser")

STYLE = """
<style>
 body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#222}
 .box{border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:12px 0}
 li{margin:4px 0}
 .pts{color:#c62828}
 .info{color:#777}
</style>
"""


def page(body):
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>Phishing Analyser</title>{STYLE}</head><body>{body}</body></html>")


def render_report(r):
    color = COLORS[r["verdict"]]
    out = [
        f"<h2>Verdict: <span style='color:{color}'>{r['verdict']}</span> ({r['total']} points)</h2>",
        f"<p><b>Subject:</b> {escape(str(r['subject']))}<br><b>From:</b> {escape(str(r['from']))}</p>",
    ]
    if r["override_note"]:
        out.append(f"<p><i>{escape(r['override_note'])}</i></p>")

    out.append("<div class='box'><b>Top reasons</b><ul>")
    if not r["top_reasons"]:
        out.append("<li class='info'>No suspicious findings.</li>")
    for f in r["top_reasons"]:
        out.append(f"<li>{escape(f['detail'])} <span class='pts'>+{f['points']}</span></li>")
    out.append("</ul></div>")

    for name, sec in r["sections"].items():
        out.append(f"<div class='box'><b>{escape(name)}</b> ({sec['score']} points)<ul>")
        if not sec["findings"]:
            out.append("<li class='info'>Nothing found</li>")
        for f in sec["findings"]:
            cls = "pts" if f["points"] > 0 else "info"
            out.append(f"<li class='{cls}'>{escape(f['detail'])} (+{f['points']})</li>")
        out.append("</ul></div>")
    return "".join(out)


async def run_analysis(file: UploadFile):
    if not (file.filename or "").lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB)")
    try:
        return analyze(parse_eml_bytes(raw))
    except Exception:
        raise HTTPException(status_code=422, detail="Could not parse this email")


@app.get("/", response_class=HTMLResponse)
def index():
    return page("""
<h1>Phishing Email Analyser</h1>
<p>Upload a .eml file. It is analysed in memory and never saved.
Links are never visited and attachments are never opened.</p>
<form action="/analyze" method="post" enctype="multipart/form-data">
  <input type="file" name="file" accept=".eml" required>
  <button type="submit">Analyse</button>
</form>
""")


@app.post("/analyze", response_class=HTMLResponse)
async def analyze_page(file: UploadFile = File(...)):
    report = await run_analysis(file)
    return page(render_report(report) + "<p><a href='/'>Analyse another email</a></p>")


@app.post("/api/analyze")
async def analyze_api(file: UploadFile = File(...)):
    return await run_analysis(file)
