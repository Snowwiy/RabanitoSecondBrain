"""Reviewed publisher-version references, not byte-pinned or downloaded datasets."""
from __future__ import annotations

import re
from datetime import date
from urllib.parse import urlsplit

from .cyber.model import public_url, text


def day(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("invalid_security_release_date")
    try:
        date.fromisoformat(value)
    except ValueError:
        raise ValueError("invalid_security_release_date") from None
    return value


def publication_date(value: object) -> tuple[str, str]:
    """Preserve publisher precision: a month does not imply its first day."""
    if isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}", value):
        try:
            date.fromisoformat(value + "-01")  # Validation only, never persisted.
        except ValueError:
            raise ValueError("invalid_security_release_date") from None
        return value, "month"
    return day(value), "day"


def validate_releases(raw: object, official_hosts: set[str], validate_id) -> dict[str, dict]:
    if not isinstance(raw, dict) or len(raw) > 100:
        raise ValueError("invalid_security_releases")
    result = {}
    fields = {"version", "published_on", "verified_on", "reference_url", "pinning"}
    for key, value in raw.items():
        key = validate_id(key)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("invalid_security_release_fields")
        version = text(value["version"], 80)
        published, precision = publication_date(value["published_on"])
        verified = day(value["verified_on"])
        url = public_url(value["reference_url"])
        if (not version or published > (verified[:7] if precision == "month" else verified) or value["pinning"] != "publisher_version_reference"
                or not url or urlsplit(url).scheme != "https" or urlsplit(url).hostname not in official_hosts
                or urlsplit(url).port not in (None, 443) or urlsplit(url).query or urlsplit(url).fragment):
            raise ValueError("invalid_security_release_reference")
        result[key] = {"id": key, **value, "version": version, "reference_url": url}
        if precision == "month":
            result[key]["published_on_precision"] = "month"
    return result
