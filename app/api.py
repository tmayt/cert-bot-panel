import io
import json
import os
import re
import zipfile
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app import database as db
from app.certbot_service import (
    get_cert_expiry,
    get_cert_files,
    is_running,
    issue_certificate,
    read_state,
    renew_certificate,
)
from app.dns_checker import inspect_challenges, verify_domain

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

API_TOKEN = os.environ.get("CERTBOT_API_TOKEN", "").strip()

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

router = APIRouter(prefix="/api")


class DomainCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)


def require_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    if not API_TOKEN:
        return
    token = (x_api_key or "").strip()
    if not token and authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip()
    if token != API_TOKEN:
        raise HTTPException(401, "API key نامعتبر است")


def serialize_domain(domain: dict) -> dict:
    d = dict(domain)
    d["verified"] = bool(d.get("verified"))
    raw_challenges = d.get("challenges")
    if isinstance(raw_challenges, str):
        try:
            d["challenges"] = json.loads(raw_challenges) if raw_challenges else []
        except json.JSONDecodeError:
            d["challenges"] = []
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


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("*.")


def start_or_get_domain(domain: str) -> tuple[dict, bool]:
    domain = _normalize_domain(domain)
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, "فرمت دامنه نامعتبر است")
    existing = db.get_domain_by_name(domain)
    if existing and existing["status"] not in ("failed",):
        return serialize_domain(existing), False
    if existing:
        db.delete_domain(existing["id"])
    domain_id = db.create_domain(domain)
    issue_certificate(domain_id, domain)
    created = db.get_domain(domain_id)
    if not created:
        raise HTTPException(500, "دامنه ساخته نشد")
    return serialize_domain(created), True


@router.get("/health", dependencies=[Depends(require_api_key)])
async def api_health():
    return {"ok": True, "domains": len(db.list_domains())}


@router.get("/domains", dependencies=[Depends(require_api_key)])
async def api_list_domains(name: str | None = None):
    if name:
        domain = db.get_domain_by_name(_normalize_domain(name))
        if not domain:
            return []
        return [serialize_domain(domain)]
    return [serialize_domain(d) for d in db.list_domains()]


@router.post("/domains", dependencies=[Depends(require_api_key)])
async def api_add_domain(payload: DomainCreate, response: Response):
    domain, created = start_or_get_domain(payload.domain)
    response.status_code = 201 if created else 200
    return domain


@router.get("/domains/{domain_id}", dependencies=[Depends(require_api_key)])
async def api_get_domain(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    return serialize_domain(domain)


@router.post("/domains/{domain_id}/verify", dependencies=[Depends(require_api_key)])
async def api_verify_dns(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if domain["status"] not in ("pending_dns", "renewing"):
        raise HTTPException(400, "وضعیت فعلی اجازه تأیید نمی‌دهد")
    ok, message = verify_domain(domain_id)
    updated = serialize_domain(db.get_domain(domain_id))
    if not ok:
        raise HTTPException(400, message)
    return {"ok": True, "message": message, "domain": updated}


@router.post("/domains/{domain_id}/renew", dependencies=[Depends(require_api_key)])
async def api_renew(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات دیگری در حال اجراست")
    renew_certificate(domain_id, domain["domain"])
    return serialize_domain(db.get_domain(domain_id))


@router.post("/domains/{domain_id}/retry", dependencies=[Depends(require_api_key)])
async def api_retry(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات دیگری در حال اجراست")
    issue_certificate(domain_id, domain["domain"])
    return serialize_domain(db.get_domain(domain_id))


@router.delete("/domains/{domain_id}", dependencies=[Depends(require_api_key)])
async def api_delete_domain(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    if is_running(domain_id):
        raise HTTPException(400, "عملیات در حال اجراست")
    db.delete_domain(domain_id)
    return {"ok": True}


@router.get("/domains/{domain_id}/certificate", dependencies=[Depends(require_api_key)])
async def api_certificate_pems(domain_id: int):
    domain = db.get_domain(domain_id)
    if not domain:
        raise HTTPException(404, "دامنه یافت نشد")
    files = get_cert_files(domain["domain"])
    if not files:
        raise HTTPException(404, "گواهی یافت نشد")
    contents = {name: path.read_text() for name, path in files.items()}
    return {
        "domain": domain["domain"],
        "expires_at": domain.get("cert_expires_at") or get_cert_expiry(domain["domain"]),
        "files": contents,
    }


@router.get("/domains/{domain_id}/download", dependencies=[Depends(require_api_key)])
async def api_download_cert(domain_id: int):
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
