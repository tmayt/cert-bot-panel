import io
import re
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app import database as db
from app.certbot_service import get_cert_expiry, get_cert_files, is_running, issue_certificate, read_state, renew_certificate
from app.database import init_db
from app.dns_checker import inspect_challenges, verify_domain

app = FastAPI(title="Certbot Panel", description="پنل مدیریت گواهی SSL با DNS Challenge")

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

STATUS_LABELS = {
    "pending_dns": "در انتظار DNS",
    "verifying": "در حال بررسی",
    "issuing": "در حال صدور",
    "active": "فعال",
    "failed": "خطا",
    "renewing": "در حال تمدید",
}

STATUS_COLORS = {
    "pending_dns": "warning",
    "verifying": "info",
    "issuing": "info",
    "active": "success",
    "failed": "danger",
    "renewing": "info",
}


@app.on_event("startup")
def startup():
    init_db()


def _enrich_domain(domain: dict) -> dict:
    d = dict(domain)
    d["status_label"] = STATUS_LABELS.get(d["status"], d["status"])
    d["status_color"] = STATUS_COLORS.get(d["status"], "secondary")
    d["is_running"] = is_running(d["id"])
    state = read_state(d["id"]) or {}
    d["waiting_challenge"] = state.get("current")
    challenges = db.get_challenges(d["id"])
    d["challenges"] = challenges
    if challenges and d["status"] in ("pending_dns", "renewing"):
        d["challenges"] = inspect_challenges(challenges)
    if d["status"] == "active" and not d.get("cert_expires_at"):
        d["cert_expires_at"] = get_cert_expiry(d["domain"])
    return d


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    domains = [_enrich_domain(d) for d in db.list_domains()]
    return templates.TemplateResponse("index.html", {
        "request": request,
        "domains": domains,
    })


@app.post("/domains/add")
async def add_domain(domain: str = Form(...)):
    domain = domain.strip().lower().removeprefix("*.")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, "فرمت دامنه نامعتبر است")
    existing = db.get_domain_by_name(domain)
    if existing and existing["status"] not in ("failed",):
        raise HTTPException(400, "این دامنه قبلاً ثبت شده است")
    if existing:
        db.delete_domain(existing["id"])
    domain_id = db.create_domain(domain)
    issue_certificate(domain_id, domain)
    return RedirectResponse(f"/domains/{domain_id}", status_code=303)


@app.get("/domains/{domain_id}", response_class=HTMLResponse)
async def domain_detail(request: Request, domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    domain = _enrich_domain(domain)
    return templates.TemplateResponse("domain.html", {
        "request": request,
        "domain": domain,
    })


@app.post("/domains/{domain_id}/verify")
async def verify_dns(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if domain["status"] not in ("pending_dns", "renewing"):
        raise HTTPException(400, "وضعیت فعلی اجازه تأیید نمی‌دهد")
    ok, message = verify_domain(domain_id)
    if not ok:
        return RedirectResponse(
            f"/domains/{domain_id}?error={quote(message)}",
            status_code=303,
        )
    return RedirectResponse(
        f"/domains/{domain_id}?success={quote(message)}",
        status_code=303,
    )


@app.post("/domains/{domain_id}/renew")
async def renew(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات دیگری در حال اجراست")
    renew_certificate(domain_id, domain["domain"])
    return RedirectResponse(f"/domains/{domain_id}", status_code=303)


@app.post("/domains/{domain_id}/retry")
async def retry(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات دیگری در حال اجراست")
    issue_certificate(domain_id, domain["domain"])
    return RedirectResponse(f"/domains/{domain_id}", status_code=303)


@app.post("/domains/{domain_id}/delete")
async def delete_domain(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات در حال اجراست")
    db.delete_domain(domain_id)
    return RedirectResponse("/", status_code=303)


@app.get("/domains/{domain_id}/download")
async def download_cert(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    files = get_cert_files(domain["domain"])
    if not files:
        raise HTTPException(404, "گواهی یافت نشد")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, path in files.items():
            zf.write(path, f"{domain['domain']}/{name}")
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{domain["domain"]}.zip"'
        },
    )


@app.get("/api/domains")
async def api_list_domains():
    return [_enrich_domain(d) for d in db.list_domains()]


@app.get("/api/domains/{domain_id}")
async def api_get_domain(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404)
    return _enrich_domain(domain)
