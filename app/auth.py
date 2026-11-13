import hmac
import os
import secrets
import threading
import time
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


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# 0 disables the limit. Window is how long failed attempts are remembered.
LOGIN_MAX_ATTEMPTS = _env_int("LOGIN_MAX_ATTEMPTS", 5)
LOGIN_WINDOW_SECONDS = max(_env_int("LOGIN_WINDOW_SECONDS", 900), 1)


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


def client_address(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def format_retry_wait(seconds: int) -> str:
    seconds = max(int(seconds), 1)
    if seconds < 60:
        return f"{seconds} ثانیه"
    minutes = (seconds + 59) // 60
    return f"{minutes} دقیقه"


def lock_message(seconds: int) -> str:
    return f"تلاش‌های ورود موقتاً محدود شده است. حدود {format_retry_wait(seconds)} دیگر دوباره امتحان کنید."


class LoginRateLimiter:
    """Failed login attempts per client address, inside one process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        kept = [stamp for stamp in self._failures.get(key, []) if now - stamp < LOGIN_WINDOW_SECONDS]
        if kept:
            self._failures[key] = kept
        else:
            self._failures.pop(key, None)
        return kept

    def _wait(self, stamps: list[float], now: float) -> int:
        if LOGIN_MAX_ATTEMPTS <= 0 or len(stamps) < LOGIN_MAX_ATTEMPTS:
            return 0
        remaining = int(LOGIN_WINDOW_SECONDS - (now - stamps[0])) + 1
        return max(remaining, 1)

    def retry_after(self, key: str) -> int:
        if LOGIN_MAX_ATTEMPTS <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            return self._wait(self._prune(key, now), now)

    def record_failure(self, key: str) -> int:
        if LOGIN_MAX_ATTEMPTS <= 0:
            return 0
        now = time.monotonic()
        with self._lock:
            stamps = self._prune(key, now)
            if len(stamps) >= LOGIN_MAX_ATTEMPTS:
                return self._wait(stamps, now)
            stamps.append(now)
            self._failures[key] = stamps
            return self._wait(stamps, now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


login_rate_limiter = LoginRateLimiter()


async def require_login(request: Request, call_next):
    if is_public_path(request.url.path) or is_authenticated(request):
        return await call_next(request)
    if request.method in ("GET", "HEAD"):
        nxt = quote(request.url.path, safe="/")
        return RedirectResponse(f"/login?next={nxt}", status_code=303)
    return RedirectResponse("/login", status_code=303)
