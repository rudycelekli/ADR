"""Where each agent keeps its config files and ADR's plugin."""

import hashlib
import os
from pathlib import Path

from ..storage.files import read_private_json

HARNESS_LABELS = {
    "claude": "Claude Code",
    "codex": "Codex",
    "opencode": "opencode",
    "copilot": "GitHub Copilot CLI",
}
PLUGIN_NAME = "adr-agent"
SCHEMA = 1


def configuration_path(harness: str, home: Path | None = None) -> Path:
    explicit_home = home is not None
    home = home or Path.home()
    if harness == "claude":
        return home / ".claude" / "settings.json"
    if harness == "copilot":
        return home / ".copilot" / "hooks" / "adr-desktop.json"
    if harness == "codex":
        root = home / ".codex" if explicit_home else Path(os.environ.get("CODEX_HOME", str(home / ".codex")))
        return root / "hooks.json"
    if harness == "opencode":
        root = (
            home / ".config"
            if explicit_home
            else Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        )
        return root / "opencode" / "plugins" / "adr-desktop.js"
    raise ValueError("Unsupported hook harness")


def directory(state_dir: Path, harness: str) -> Path:
    if harness not in HARNESS_LABELS:
        raise ValueError("Unknown ADR agent integration")
    return state_dir / "agent-plugins" / harness


def check_location(state_dir, harness):
    for parent in (directory(state_dir, harness), *directory(state_dir, harness).parents):
        if parent == state_dir:
            break
        if parent.is_symlink():
            raise ValueError("The ADR integration directory must not contain symlinks")


def read_receipt(state_dir: Path, harness: str):
    check_location(state_dir, harness)
    file = directory(state_dir, harness) / "installation.json"
    if not file.exists():
        return None
    value = read_private_json(file, maximum=128 * 1024)
    if value.get("schema") != SCHEMA or value.get("harness") != harness:
        raise ValueError("The saved ADR integration needs manual review")
    return value


def bundle_root(state_dir, harness):
    return directory(state_dir, harness) / "catalog" / "plugins" / PLUGIN_NAME


def bundle_matches(root: Path, receipt: dict) -> bool:
    try:
        for relative, digest in receipt["files"].items():
            relative = Path(relative)
            if relative.is_absolute() or ".." in relative.parts:
                return False
            file = root / relative
            if file.is_symlink() or file.stat().st_size > 1024 * 1024:
                return False
            if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
                return False
        return bool(receipt["files"])
    except (OSError, ValueError, KeyError, TypeError):
        return False


def configured(state_dir, harness):
    try:
        receipt = read_receipt(state_dir, harness)
        return bool(
            receipt
            and receipt.get("status") == "configured"
            and bundle_matches(bundle_root(state_dir, harness), receipt)
        )
    except (OSError, ValueError):
        return False


def opencode_plugin_installed(home: Path | None = None, *, state_dir: Path | None = None) -> bool:
    """ADR's opencode plugin file is in place and, given a state folder, unchanged since ADR wrote it."""
    try:
        source = configuration_path("opencode", home).read_bytes()
        if state_dir is not None:
            record = read_private_json(state_dir / "opencode-plugin.json")
            if record.get("digest") != hashlib.sha256(source).hexdigest():
                return False
        return source.startswith(b"// ADR managed plugin: adr-desktop-file-guard")
    except (OSError, ValueError, AttributeError, TypeError):
        return False


def plugin_root(state_dir, harness):
    """Use the root supplied by the native plugin host, not a model-supplied path."""
    receipt = read_receipt(state_dir, harness)
    if not receipt or receipt.get("status") != "configured":
        return None
    if harness == "opencode" and not opencode_plugin_installed(state_dir=state_dir):
        return None
    value = (
        os.environ.get("ADR_PLUGIN_ROOT")
        if harness == "opencode"
        else os.environ.get("CLAUDE_PLUGIN_ROOT")
        or os.environ.get("PLUGIN_ROOT")
        or os.environ.get("COPILOT_PLUGIN_ROOT")
    )
    if not value or not Path(value).is_absolute():
        return None
    root = Path(value).resolve()
    return root if bundle_matches(root, receipt) else None
