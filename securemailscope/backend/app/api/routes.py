import tempfile
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from ..core.pipeline import analyze_pcap
from ..core.report_generator import to_json, to_html, to_pdf

router = APIRouter()

# In-memory store of the last analysis per session (swap for SQLite/Postgres in production)
_LAST_REPORT = {}


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(400, "Please upload a .pcap or .pcapng file")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        report = analyze_pcap(tmp_path, filename=file.filename)
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {e}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    _LAST_REPORT["report"] = report
    return report.model_dump()


@router.get("/report/json")
def get_report_json():
    report = _LAST_REPORT.get("report")
    if not report:
        raise HTTPException(404, "No analysis has been run yet")
    out = "/tmp/securemailscope_report.json"
    to_json(report, out)
    return FileResponse(out, filename="securemailscope_report.json")


@router.get("/report/html")
def get_report_html():
    report = _LAST_REPORT.get("report")
    if not report:
        raise HTTPException(404, "No analysis has been run yet")
    out = "/tmp/securemailscope_report.html"
    to_html(report, out)
    return FileResponse(out, filename="securemailscope_report.html")


@router.get("/report/pdf")
def get_report_pdf():
    report = _LAST_REPORT.get("report")
    if not report:
        raise HTTPException(404, "No analysis has been run yet")
    out = "/tmp/securemailscope_report.pdf"
    try:
        to_pdf(report, out)
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed (check weasyprint system deps): {e}")
    return FileResponse(out, filename="securemailscope_report.pdf")
