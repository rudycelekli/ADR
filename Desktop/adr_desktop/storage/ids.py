"""Stable random IDs and timestamps for rows and profile records. Light enough for the hook path."""

import uuid
from datetime import datetime, timezone


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
