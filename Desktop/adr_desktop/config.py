"""Private local state. No cloud endpoint, telemetry SDK, or remote control plane."""

import hashlib
import os
import platform
import secrets
import sys
from pathlib import Path

from .storage.ids import utcnow as utcnow  # Desktop's flat modules import it from here.

MAX_STATE_BYTES = 1024 * 1024 * 1024
CAPTURE_INTERVAL_SECONDS = (300, 900, 1800, 3600)
DEFAULT_SETTINGS = {
    "recording": False,
    "interval_seconds": CAPTURE_INTERVAL_SECONDS[0],
    "history_days": 14,
    "protection_enabled": True,
    "opaque_tools": "ask",
    "inventory_enabled": False,
    "onboarding_complete": False,
}


def token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def command_prefix() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "adr_desktop"]


def platform_label() -> str:
    return {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(
        platform.system(), platform.system()
    )


class InstanceLock:
    """OS-held process lock, rather than trusting a PID from a stale file."""

    def __init__(self, state_dir: Path):
        self.handle = (state_dir / "instance.lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.handle.seek(0)
                self.handle.write(b"0")
                self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                os.fchmod(self.handle.fileno(), 0o600)
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RuntimeError("ADR Desktop is already running for this profile") from None

    def close(self):
        self.handle.close()
