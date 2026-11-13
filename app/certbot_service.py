import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from app import database as db

STATE_DIR = os.environ.get("STATE_DIR", "/data/state")
CONFIG_DIR = os.environ.get("CERTBOT_CONFIG_DIR", "/data/letsencrypt")
WORK_DIR = os.environ.get("CERTBOT_WORK_DIR", "/data/letsencrypt/work")
LOGS_DIR = os.environ.get("CERTBOT_LOGS_DIR", "/data/letsencrypt/logs")
EMAIL = os.environ.get("LETSENCRYPT_EMAIL", "admin@example.com")
STAGING = os.environ.get("CERTBOT_STAGING", "false").lower() in ("1", "true", "yes")

_running: dict[int, subprocess.Popen] = {}
_lock = threading.Lock()


def _state_file(domain_id: int) -> Path:
    return Path(STATE_DIR) / f"domain_{domain_id}.json"


def write_state(domain_id: int, data: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    path = _state_file(domain_id)
    path.write_text(json.dumps(data))


def read_state(domain_id: int) -> dict | None:
    path = _state_file(domain_id)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def clear_state(domain_id: int) -> None:
    path = _state_file(domain_id)
    if path.exists():
        path.unlink()


def cert_path(domain: str) -> Path:
    return Path(CONFIG_DIR) / "live" / domain


def get_cert_expiry(domain: str) -> str | None:
    cert_file = cert_path(domain) / "fullchain.pem"
    if not cert_file.exists():
        return None
    try:
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(cert_file)],
            capture_output=True,
            text=True,
            check=True,
        )
        # notAfter=Jul  7 12:00:00 2026 GMT
        date_str = result.stdout.strip().split("=", 1)[1]
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return None


def _build_certbot_cmd(domain: str, domain_id: int, renew: bool = False) -> list[str]:
    hooks_dir = Path(__file__).parent.parent / "hooks"
    cmd = [
        "certbot",
        "renew" if renew else "certonly",
        "--manual",
        "--preferred-challenges", "dns",
        "--manual-auth-hook", str(hooks_dir / "auth_hook.py"),
        "--manual-cleanup-hook", str(hooks_dir / "cleanup_hook.py"),
        "--non-interactive",
        "--agree-tos",
        "--email", EMAIL,
        "--config-dir", CONFIG_DIR,
        "--work-dir", WORK_DIR,
        "--logs-dir", LOGS_DIR,
    ]
    if STAGING:
        cmd.append("--staging")
    if renew:
        cmd.extend(["--cert-name", domain, "--force-renewal"])
    else:
        cmd.extend([
            "-d", f"*.{domain}",
            "-d", domain,
            "--cert-name", domain,
        ])
    return cmd


def _is_dns_rejection(output: str) -> bool:
    text = (output or "").lower()
    markers = (
        "dns problem",
        "no txt record",
        "incorrect txt",
        "nxdomain",
        "servfail",
        "challenge failed",
        "some challenges have failed",
        "unauthorized",
        "secondary validation",
        "timeout waiting for dns",
        "dns validation",
    )
    return any(marker in text for marker in markers)


def _finish_failure(domain_id: int, output: str) -> None:
    message = (output or "certbot failed")[-2000:]
    current = db.get_domain(domain_id) or {}
    challenges = db.get_challenges(domain_id)
    same_step = bool(challenges) and (
        _is_dns_rejection(output) or current.get("status") == "verifying"
    )
    if same_step:
        db.mark_dns_rejected(domain_id, message)
    else:
        db.mark_failed(domain_id, message)


def _run_certbot(domain_id: int, domain: str, renew: bool = False) -> None:
    write_state(domain_id, {
        "domain_id": domain_id,
        "domain": domain,
        "verified": False,
        "awaiting_user": False,
        "challenges_reset": False,
        "renew": renew,
    })

    env = os.environ.copy()
    env["DOMAIN_ID"] = str(domain_id)
    env["APP_DIR"] = str(Path(__file__).parent.parent)
    env["PYTHONPATH"] = str(Path(__file__).parent.parent)

    cmd = _build_certbot_cmd(domain, domain_id, renew=renew)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        with _lock:
            _running[domain_id] = proc
        output, _ = proc.communicate()

        if proc.returncode == 0:
            expires = get_cert_expiry(domain)
            db.mark_active(domain_id, expires)
        else:
            _finish_failure(domain_id, output or "")
    except Exception as e:
        db.mark_failed(domain_id, str(e))
    finally:
        with _lock:
            _running.pop(domain_id, None)
        clear_state(domain_id)


def issue_certificate(domain_id: int, domain: str) -> None:
    db.mark_issuing(domain_id)
    thread = threading.Thread(target=_run_certbot, args=(domain_id, domain), daemon=True)
    thread.start()


def renew_certificate(domain_id: int, domain: str) -> None:
    db.mark_renewing(domain_id)
    thread = threading.Thread(
        target=_run_certbot, args=(domain_id, domain, True), daemon=True
    )
    thread.start()


def retry_certificate(domain_id: int, domain: str) -> None:
    """Retry a Let's Encrypt DNS rejection without restarting issuance from scratch."""
    current = db.get_domain(domain_id)
    challenges = db.get_challenges(domain_id)
    if current and current["status"] == "dns_rejected" and challenges:
        db.mark_dns_retry(domain_id)
        renew = bool(current.get("cert_expires_at") or get_cert_files(domain))
        thread = threading.Thread(
            target=_run_certbot, args=(domain_id, domain, renew), daemon=True
        )
        thread.start()
        return
    issue_certificate(domain_id, domain)


def is_running(domain_id: int) -> bool:
    with _lock:
        proc = _running.get(domain_id)
        if proc and proc.poll() is None:
            return True
        return False


def get_cert_files(domain: str) -> dict[str, Path] | None:
    base = cert_path(domain)
    if not base.exists():
        return None
    files = {}
    for name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
        path = base / name
        if path.exists():
            files[name] = path
    return files if files else None
