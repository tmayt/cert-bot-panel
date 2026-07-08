import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/data/db/certbot.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending_dns',
                txt_name TEXT,
                txt_value TEXT,
                challenges TEXT DEFAULT '[]',
                verified INTEGER DEFAULT 0,
                error_message TEXT,
                cert_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        # migration for existing DBs
        cols = {row[1] for row in conn.execute("PRAGMA table_info(domains)")}
        if "challenges" not in cols:
            conn.execute("ALTER TABLE domains ADD COLUMN challenges TEXT DEFAULT '[]'")
        conn.commit()


def get_challenges(domain_id: int) -> list[dict]:
    domain = get_domain(domain_id)
    if not domain:
        return []
    raw = domain.get("challenges") or "[]"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def add_challenge(domain_id: int, certbot_domain: str, txt_name: str, txt_value: str) -> list[dict]:
    challenges = get_challenges(domain_id)
    challenges.append({
        "certbot_domain": certbot_domain,
        "txt_name": txt_name,
        "txt_value": txt_value,
    })
    update_domain(
        domain_id,
        challenges=json.dumps(challenges),
        txt_name=txt_name,
        txt_value=txt_value,
        verified=0,
        status="pending_dns",
        error_message=None,
    )
    return challenges


@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def create_domain(domain: str) -> int:
    now = _now()
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO domains (domain, status, created_at, updated_at) VALUES (?, 'pending_dns', ?, ?)",
            (domain, now, now),
        )
        conn.commit()
        return cursor.lastrowid


def get_domain(domain_id: int) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
        return dict(row) if row else None


def get_domain_by_name(domain: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM domains WHERE domain = ?", (domain,)).fetchone()
        return dict(row) if row else None


def list_domains() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM domains ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def update_domain(domain_id: int, **fields) -> None:
    fields["updated_at"] = _now()
    sets = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [domain_id]
    with get_db() as conn:
        conn.execute(f"UPDATE domains SET {sets} WHERE id = ?", values)
        conn.commit()


def set_challenge(domain_id: int, txt_name: str, txt_value: str) -> None:
    update_domain(
        domain_id,
        txt_name=txt_name,
        txt_value=txt_value,
        verified=0,
        status="pending_dns",
        error_message=None,
    )


def mark_verified(domain_id: int) -> None:
    update_domain(domain_id, verified=1, status="verifying")


def mark_active(domain_id: int, expires_at: str | None = None) -> None:
    update_domain(
        domain_id,
        status="active",
        verified=0,
        txt_name=None,
        txt_value=None,
        challenges="[]",
        error_message=None,
        cert_expires_at=expires_at,
    )


def mark_failed(domain_id: int, error: str) -> None:
    update_domain(domain_id, status="failed", error_message=error, verified=0)


def mark_issuing(domain_id: int) -> None:
    update_domain(
        domain_id,
        status="issuing",
        verified=0,
        txt_name=None,
        txt_value=None,
        challenges="[]",
        error_message=None,
    )


def mark_renewing(domain_id: int) -> None:
    update_domain(
        domain_id,
        status="renewing",
        verified=0,
        txt_name=None,
        txt_value=None,
        challenges="[]",
        error_message=None,
    )


def delete_domain(domain_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        conn.commit()
