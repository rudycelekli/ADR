"""Row and record timestamps. Imports only datetime, which the hook already loads."""

from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
