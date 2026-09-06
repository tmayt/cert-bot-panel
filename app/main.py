import io
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from app.api import DOMAIN_RE, router as api_router, serialize_domain
from app.certbot_service import get_cert_files, is_running, issue_certificate, renew_certificate
from app.database import init_db
from app.dns_checker import verify_domain

app = FastAPI(title="Certbot Panel", description="پنل مدیریت گواهی SSL با DNS Challenge")
app.include_router(api_router)

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    from app import database as db

    domains = [serialize_domain(d) for d in db.list_domains()]
    return templates.TemplateResponse("index.html", {
        "request": request,
        "domains": domains,
    })


@app.post("/domains/add")
async def add_domain(domain: str = Form(...)):
    from app import database as db

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
    from app import database as db

    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    domain = serialize_domain(domain)
    return templates.TemplateResponse("domain.html", {
        "request": request,
        "domain": domain,
    })


@app.post("/domains/{domain_id}/verify")
async def verify_dns(domain_id: int):
    from app import database as db

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
    from app import database as db

    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات دیگری در حال اجراست")
    renew_certificate(domain_id, domain["domain"])
    return RedirectResponse(f"/domains/{domain_id}", status_code=303)


@app.post("/domains/{domain_id}/retry")
async def retry(domain_id: int):
    from app import database as db

    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات دیگری در حال اجراست")
    issue_certificate(domain_id, domain["domain"])
    return RedirectResponse(f"/domains/{domain_id}", status_code=303)


@app.post("/domains/{domain_id}/delete")
async def delete_domain(domain_id: int):
    from app import database as db

    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات در حال اجراست")
    db.delete_domain(domain_id)
    return RedirectResponse("/", status_code=303)


@app.get("/domains/{domain_id}/download")
async def download_cert(domain_id: int):
    from app import database as db

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
