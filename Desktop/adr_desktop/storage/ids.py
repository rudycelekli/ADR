"""Stable random IDs for rows and profile records. Light enough for the hook path."""

import uuid


def new_id() -> str:
    return uuid.uuid4().hex
