"""Pre-tool file policy. Hooks are cooperative controls, not a kernel sandbox."""

import os
import platform
import unicodedata
from pathlib import Path

from ..detection.contracts import Operation
from ..detection.operation import (
    DIRECT_TOOLS,
    PATH_KEYS,
    SAFE_TOOLS,
    SEARCH_TOOLS,
    SHELL_TOOLS,
    literal_shell_files,
    printable,
    resolve_path,
)
from .contracts import DENIAL_REASONS, Decision


def _comparison(path: Path) -> str:
    value = unicodedata.normalize("NFC", str(path))
    # Conservative on macOS/Windows: overblocking a case-sensitive volume is
    # preferable to a case-variant bypass on the common case-insensitive volume.
    return value.casefold() if platform.system() in ("Darwin", "Windows") else value


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _within(candidate: Path, directory: Path) -> bool:
    expected = _comparison(directory)
    for ancestor in (candidate, *candidate.parents):
        if _comparison(ancestor) == expected or _same_file(ancestor, directory):
            return True
    return False


def validate_rule(path: str, action: str, kind: str, label: str) -> dict:
    original = Path(path).expanduser()
    if not original.is_absolute():
        raise ValueError("Choose an absolute path or a path beginning with ~/")
    if action not in ("ask", "block") or kind not in ("file", "directory"):
        raise ValueError("Choose ask/block and file/directory")
    resolved = resolve_path(path, str(Path.home()))
    if resolved == Path(resolved.anchor):
        raise ValueError("Protect a specific file or directory, not the filesystem root")
    return {
        "path": str(original.absolute()),
        "action": action,
        "kind": kind,
        "label": printable(label.strip() or resolved.name)[:100],
    }


def evaluate(operation: Operation, snapshot: dict) -> Decision:
    harness, tool, arguments, cwd = operation.harness, operation.tool, operation.arguments, operation.cwd
    result = Decision(tool=tool, session_id=operation.session_id)
    rules = list(snapshot.get("rules", [])) if snapshot.get("enabled", True) else []
    # Control files remain protected even when user file rules are paused.
    rules += [
        {
            "id": "adr-control-plane",
            "path": path,
            "kind": kind,
            "action": "block",
            "label": "ADR security configuration",
        }
        for path, kind in snapshot.get("control_paths", [])
    ]
    if snapshot.get("control_paths"):
        # A project-local configuration can also weaken a user-level hook.
        project_controls = (
            (
                (".claude/settings.json", "file"),
                (".claude/settings.local.json", "file"),
                (".mcp.json", "file"),
            )
            if harness == "claude"
            else ((".codex/hooks.json", "file"), (".codex/config.toml", "file"))
            if harness == "codex"
            else (
                (".opencode/plugins", "directory"),
                (".opencode/plugin", "directory"),
                ("opencode.json", "file"),
                ("opencode.jsonc", "file"),
            )
            if harness == "opencode"
            else ((".github/hooks", "directory"),)
        )
        rules += [
            {
                "id": "adr-control-plane",
                "path": str(root / name),
                "kind": kind,
                "action": "block",
                "label": "Agent hook configuration",
            }
            for root in (Path(cwd), *Path(cwd).parents)
            for name, kind in project_controls
        ]
    if not rules:
        return result
    name = tool.lower()
    if name in SAFE_TOOLS:
        return result
    paths = []
    for key in PATH_KEYS:
        value = arguments.get(key)
        if value is not None:
            paths.append(resolve_path(value, cwd))
    if name in SHELL_TOOLS:
        paths.extend(literal_shell_files(arguments, cwd))
    if name in SEARCH_TOOLS and not paths:
        paths.append(resolve_path(cwd, cwd))
    result.paths = [str(path) for path in paths]
    if name in DIRECT_TOOLS and not paths:
        result.decision, result.reason = "deny", "ADR could not determine the file being accessed"
        result.reason_code = "invalid_request"
        return result

    matches = []
    for rule in rules:
        protected = resolve_path(rule["path"], cwd)
        for path in paths:
            exact = _comparison(path) == _comparison(protected) or _same_file(path, protected)
            contained = rule["kind"] == "directory" and _within(path, protected)
            # A recursive query of an ancestor can read the protected descendant.
            ancestor_query = name in SEARCH_TOOLS and _within(protected, path)
            if exact or contained or ancestor_query:
                matches.append(rule)
                break
    if matches:
        rule = next((item for item in matches if item["action"] == "block"), matches[0])
        result.rule_id = rule["id"]
        result.reason_code = "protected_path"
        result.decision = "deny" if rule["action"] == "block" else "ask"
        action = "blocked" if result.decision == "deny" else "requires your approval"
        result.reason = f"ADR: {rule['label']} is protected; this access is {action}."
        strict = snapshot.get("strict_execution", snapshot.get("opaque_tools") == "block")
        if not isinstance(strict, bool):
            raise ValueError("Invalid strict execution setting")
        if (
            result.decision == "ask" and name in SHELL_TOOLS
            and strict and snapshot.get("opaque_tools") == "block"
        ):
            # A file's Ask rule must never weaken an explicit Block-all-
            # execution choice merely because its literal path is recognized.
            result.decision = "deny"
            result.reason_code = "execution_policy"
            result.reason = DENIAL_REASONS["execution_policy"]
        return result
    if name not in DIRECT_TOOLS | SEARCH_TOOLS:
        strict = snapshot.get("strict_execution", snapshot.get("opaque_tools") == "block")
        if not isinstance(strict, bool):
            raise ValueError("Invalid strict execution setting")
        if strict:
            result.decision = "deny" if snapshot.get("opaque_tools") == "block" else "ask"
            result.reason_code = "execution_policy"
            result.reason = (
                DENIAL_REASONS["execution_policy"] if result.decision == "deny"
                else "Strict execution review is enabled. Review this command or unrecognized tool."
            )
    return result
