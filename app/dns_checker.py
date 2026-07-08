import time

import dns.resolver

from app import database as db
from app.certbot_service import read_state, write_state
from app.dns_utils import get_txt_values


def _format_found(values: list[str]) -> str:
    if not values:
        return "(هیچ مقداری یافت نشد)"
    return "، ".join(values)


def check_txt_record(txt_name: str, expected_value: str, retries: int = 5) -> tuple[bool, str, list[str]]:
    last_error = "رکورد یافت نشد"
    last_found: list[str] = []
    for attempt in range(retries):
        try:
            found = get_txt_values(txt_name)
            last_found = found
            if expected_value in found:
                return True, "رکورد DNS تأیید شد", found
            if found:
                last_error = (
                    f"مقدار TXT یافت شد اما مطابقت ندارد. "
                    f"انتظار: {expected_value} | یافت‌شده: {_format_found(found)}"
                )
            else:
                last_error = "رکورد TXT هنوز propagate نشده"
        except dns.resolver.NXDOMAIN:
            last_error = "دامنه یافت نشد"
            last_found = []
        except dns.resolver.NoAnswer:
            last_error = "رکورد TXT هنوز propagate نشده"
            last_found = []
        except dns.resolver.Timeout:
            last_error = "timeout در بررسی DNS"
        except Exception as e:
            last_error = str(e)

        if attempt < retries - 1:
            time.sleep(3)

    if last_found and expected_value not in last_found:
        last_error = (
            f"مقدار TXT یافت شد اما مطابقت ندارد. "
            f"انتظار: {expected_value} | یافت‌شده: {_format_found(last_found)}"
        )
    return False, last_error, last_found


def inspect_challenges(challenges: list[dict]) -> list[dict]:
    """Check current DNS state for each challenge without retries."""
    dns_cache: dict[str, list[str] | None] = {}
    results = []

    for ch in challenges:
        txt_name = ch["txt_name"]
        expected = ch["txt_value"]
        if txt_name not in dns_cache:
            try:
                dns_cache[txt_name] = get_txt_values(txt_name)
            except dns.resolver.NXDOMAIN:
                dns_cache[txt_name] = None
            except Exception:
                dns_cache[txt_name] = []

        found = dns_cache[txt_name]
        if found is None:
            status = "nxdomain"
            message = "دامنه یافت نشد"
        elif not found:
            status = "missing"
            message = "رکورد TXT هنوز در DNS نیست"
        elif expected in found:
            status = "found"
            message = "مقدار صحیح یافت شد"
        else:
            status = "mismatch"
            message = f"مقادیر یافت‌شده: {_format_found(found)}"

        results.append({
            **ch,
            "dns_status": status,
            "dns_message": message,
            "dns_found": found or [],
        })

    return results


def verify_domain(domain_id: int) -> tuple[bool, str]:
    domain = db.get_domain(domain_id)
    if not domain:
        return False, "دامنه یافت نشد"

    challenges = db.get_challenges(domain_id)
    if not challenges:
        return False, "رکورد TXT هنوز آماده نشده. لطفاً چند ثانیه صبر کنید."

    state = read_state(domain_id) or {}
    current = state.get("current")
    if current:
        pending = [ch for ch in challenges if ch["certbot_domain"] == current]
        if not pending:
            pending = [challenges[-1]]
        to_check = pending
    else:
        to_check = challenges

    for ch in to_check:
        ok, message, _ = check_txt_record(ch["txt_name"], ch["txt_value"])
        if not ok:
            label = ch.get("certbot_domain") or ch["txt_name"]
            return False, f"{label}: {message}"

    db.mark_verified(domain_id)

    state = read_state(domain_id) or {}
    state["verified"] = True
    write_state(domain_id, state)

    return True, "رکوردهای DNS تأیید شد. در حال صدور گواهی..."
