"""Private profile files: the state folder, owner-only JSON files written atomically, and the
canonical, size-limited JSON they hold."""

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 8 * 1024 * 1024


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def strict_json(raw: str | bytes, max_bytes: int = MAX_JSON_BYTES) -> Any:
    if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > max_bytes:
        raise ValueError("JSON exceeds the local request limit")

    def reject(_):
        raise ValueError("Non-finite JSON is not supported")

    value = json.loads(raw, parse_constant=reject)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError("JSON is nested too deeply")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    canonical(value).encode("utf-8")
    return value


def default_state_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ADR Desktop"
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") / "ADR Desktop"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "adr-desktop"


def prepare_state_dir(value: Path | str | None = None) -> Path:
    path = Path(value or default_state_dir()).expanduser().absolute()
    if path.is_symlink():
        raise ValueError("The ADR state directory must not be a symbolic link")
    resolved = path.resolve()
    if resolved in {Path("/"), Path.home().resolve(), Path(tempfile.gettempdir()).resolve()}:
        raise ValueError("Choose a dedicated ADR state directory")
    if path.exists() and not (path / ".adr-desktop-state").exists() and any(path.iterdir()):
        raise ValueError("Refusing to use a nonempty directory that is not ADR Desktop state")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if hasattr(os, "getuid") and path.stat().st_uid != os.getuid():
        raise ValueError("ADR state must belong to the current user")
    if os.name != "nt":
        path.chmod(0o700)
    marker = path / ".adr-desktop-state"
    if not marker.exists():
        atomic_json(marker, {"format": 1})
    return path


def atomic_json(path: Path, value: Any) -> None:
    """Write a private file atomically; never follow a final-component symlink."""
    if path.is_symlink():
        raise ValueError("Refusing to replace a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = canonical(value).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".adr-", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if fd != -1:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_private_json(path: Path, *, maximum: int = MAX_JSON_BYTES) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Expected a regular ADR state file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError("ADR state file has the wrong owner")
        if os.name != "nt" and info.st_mode & 0o077:
            raise ValueError("ADR state file must be private to its owner")
        return strict_json(handle.read(maximum + 1), max_bytes=maximum)
