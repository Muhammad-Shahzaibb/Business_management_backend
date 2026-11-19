"""Small helpers for connection URLs and secret redaction."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

# postgresql://user:password@host:5432/db  ->  strip the credentials
_CREDENTIALS_RE = re.compile(r"(?<=://)[^@/\s]+@")


def redact(text: Optional[str]) -> str:
    """Remove anything that looks like credentials from an error message.

    asyncpg/Postgres errors occasionally embed the connection string; those
    messages may be shown in the superadmin portal, so credentials are
    stripped first.
    """
    if not text:
        return ""
    return _CREDENTIALS_RE.sub("***@", text)


def redact_url(url: Optional[str]) -> str:
    """Return the URL without its password (safe to display/log)."""
    if not url:
        return ""
    return redact(url)


def parse_database_url(url: Optional[str]) -> dict[str, Optional[str]]:
    """Best-effort breakdown of a Postgres URL for display purposes."""
    empty = {"host": None, "port": None, "database": None, "user": None}
    if not url:
        return empty
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return empty
    return {
        "host": parsed.hostname,
        "port": str(parsed.port) if parsed.port else None,
        "database": (parsed.path or "/").lstrip("/") or None,
        "user": parsed.username,
    }


def mask_secret(value: Optional[str], visible: int = 4) -> Optional[str]:
    """Show the last few characters of a secret so it can be recognised."""
    if not value:
        return None
    if len(value) <= visible:
        return "*" * len(value)
    return f"{'*' * 6}{value[-visible:]}"
