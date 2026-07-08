import dns.resolver


def get_txt_values(txt_name: str) -> list[str]:
    """Return all TXT values for a name (one entry per DNS RR, strings joined per RR)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    values: list[str] = []
    answers = resolver.resolve(txt_name, "TXT")
    for rdata in answers:
        value = b"".join(rdata.strings).decode("utf-8").strip('"')
        if value:
            values.append(value)
    return values


def txt_has_value(txt_name: str, expected_value: str) -> bool:
    try:
        return expected_value in get_txt_values(txt_name)
    except Exception:
        return False
