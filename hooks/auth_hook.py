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

conn = sqlite3.connect(DATABASE_PATH)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT challenges FROM domains WHERE id = ?", (domain_id,)).fetchone()

challenges = []
if row and row["challenges"]:
    try:
        challenges = json.loads(row["challenges"])
    except json.JSONDecodeError:
        challenges = []

challenges.append({
    "certbot_domain": domain,
    "txt_name": txt_name,
    "txt_value": validation,
})

conn.execute(
    """UPDATE domains SET
        challenges = ?, txt_name = ?, txt_value = ?,
        status = 'pending_dns', verified = 0
    WHERE id = ?""",
    (json.dumps(challenges), txt_name, validation, domain_id),
)
conn.commit()
conn.close()

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


def _all_challenges_present() -> bool:
    items = _load_challenges()
    if not items:
        return False
    return all(txt_has_value(ch["txt_name"], ch["txt_value"]) for ch in items)


# Certbot calls this hook once per challenge, then validates all of them.
# Exit immediately on earlier challenges so the next TXT value is issued now.
try:
    remaining = int(os.environ.get("CERTBOT_REMAINING_CHALLENGES", "0"))
except ValueError:
    remaining = 0
awaiting_user = remaining == 0

state_path = os.path.join(STATE_DIR, f"domain_{domain_id}.json")
os.makedirs(STATE_DIR, exist_ok=True)
with open(state_path, "w") as f:
    json.dump({
        "domain_id": int(domain_id),
        "verified": False,
        "current": domain,
        "awaiting_user": awaiting_user,
    }, f)

if not awaiting_user:
    sys.exit(0)

timeout = 1800
elapsed = 0
while elapsed < timeout:
    if os.path.exists(state_path):
        with open(state_path) as f:
            state = json.load(f)
        if state.get("verified"):
            if _all_challenges_present():
                sys.exit(0)
            state["verified"] = False
            state["awaiting_user"] = True
            with open(state_path, "w") as f:
                json.dump(state, f)
    time.sleep(2)
    elapsed += 2

print("Timeout waiting for DNS verification", file=sys.stderr)
sys.exit(1)
