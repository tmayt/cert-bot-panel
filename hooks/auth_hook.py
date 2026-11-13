#!/usr/bin/env python3
"""Certbot manual auth hook - saves TXT record and waits for user verification."""

import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.environ.get("APP_DIR", "/app"))

from app.dns_utils import txt_has_value

DATABASE_PATH = os.environ.get("DATABASE_PATH", "/data/db/certbot.db")
STATE_DIR = os.environ.get("STATE_DIR", "/data/state")

domain = os.environ.get("CERTBOT_DOMAIN", "")
validation = os.environ.get("CERTBOT_VALIDATION", "")
domain_id = os.environ.get("DOMAIN_ID", "")

if not domain or not validation or not domain_id:
    print("Missing CERTBOT_DOMAIN, CERTBOT_VALIDATION or DOMAIN_ID", file=sys.stderr)
    sys.exit(1)

txt_name = f"_acme-challenge.{domain.removeprefix('*.')}"
state_path = os.path.join(STATE_DIR, f"domain_{domain_id}.json")


def _read_state() -> dict:
    if not os.path.exists(state_path):
        return {}
    try:
        with open(state_path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(state: dict) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(state_path, "w") as f:
        json.dump(state, f)


def _load_challenges() -> list[dict]:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT challenges FROM domains WHERE id = ?", (domain_id,)).fetchone()
    conn.close()
    if not row or not row["challenges"]:
        return []
    try:
        return json.loads(row["challenges"])
    except json.JSONDecodeError:
        return []


def _mark_pending() -> None:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute(
        "UPDATE domains SET status = 'pending_dns', verified = 0 WHERE id = ?",
        (domain_id,),
    )
    conn.commit()
    conn.close()


def _all_challenges_present() -> bool:
    items = _load_challenges()
    if not items:
        return False
    return all(txt_has_value(ch["txt_name"], ch["txt_value"]) for ch in items)


state = _read_state()
previous = _load_challenges()
fresh_run = not state.get("challenges_reset")
if fresh_run:
    challenges = []
    if previous:
        state["values_refreshed"] = True
else:
    challenges = previous

challenges.append({
    "certbot_domain": domain,
    "txt_name": txt_name,
    "txt_value": validation,
})

conn = sqlite3.connect(DATABASE_PATH)
conn.execute(
    """UPDATE domains SET
        challenges = ?, txt_name = ?, txt_value = ?,
        status = 'pending_dns', verified = 0, error_message = NULL
    WHERE id = ?""",
    (json.dumps(challenges), txt_name, validation, domain_id),
)
conn.commit()
conn.close()

# Certbot calls this hook once per challenge, then validates all of them.
# Exit immediately on earlier challenges so the next TXT value is issued now.
try:
    remaining = int(os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0"))
except ValueError:
    remaining = 0
awaiting_user = remaining == 0

state["domain_id"] = int(domain_id)
state["verified"] = False
state["current"] = domain
state["awaiting_user"] = awaiting_user
state["challenges_reset"] = True
_write_state(state)

if not awaiting_user:
    sys.exit(0)

timeout = 1800
elapsed = 0
while elapsed < timeout:
    state = _read_state()
    if state.get("verified"):
        if _all_challenges_present():
            sys.exit(0)
        state["verified"] = False
        state["awaiting_user"] = True
        _write_state(state)
        _mark_pending()
    time.sleep(2)
    elapsed += 2

print("Timeout waiting for DNS verification", file=sys.stderr)
sys.exit(1)
