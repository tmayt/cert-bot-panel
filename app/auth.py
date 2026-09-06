import hmac
import os
import secrets
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv
from fastapi import Request
from fastapi.responses import RedirectResponse

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "").strip()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()
SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip() or secrets.token_hex(32)

PUBLIC_PATHS = {"/login", "/logout"}


def credentials_configured() -> bool:
    return bool(ADMIN_USERNAME and ADMIN_PASSWORD)


def _secure_equal(left: str, right: str) -> bool:
    left_b = left.encode("utf-8")
    right_b = right.encode("utf-8")
    if len(left_b) != len(right_b):
        hmac.compare_digest(left_b, left_b)
        return False
    return hmac.compare_digest(left_b, right_b)


def verify_credentials(username: str, password: str) -> bool:
    if not credentials_configured():
        return False
    user_ok = _secure_equal(username, ADMIN_USERNAME)
    pass_ok = _secure_equal(password, ADMIN_PASSWORD)
    return user_ok and pass_ok


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def login_user(request: Request) -> None:
    request.session["authenticated"] = True


def logout_user(request: Request) -> None:
    request.session.clear()


def safe_next_url(next_url: str | None) -> str:
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


def is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith("/api")


async def require_login(request: Request, call_next):
    if is_public_path(request.url.path) or is_authenticated(request):
        return await call_next(request)
    if request.method in ("GET", "HEAD"):
        nxt = quote(request.url.path, safe="/")
        return RedirectResponse(f"/login?next={nxt}", status_code=303)
    return RedirectResponse("/login", status_code=303)
