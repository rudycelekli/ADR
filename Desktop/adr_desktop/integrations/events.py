"""Decode each agent's hook event into an Operation, and encode a Decision back as its hook output."""

from pathlib import Path

from ..detection.contracts import Operation
from ..protection.contracts import Decision


def event_fields(event: dict, harness: str) -> tuple[str, dict, str, str]:
    if harness in ("claude", "codex", "opencode"):
        tool = event.get("tool_name")
        arguments = event.get("tool_input")
        session = event.get("session_id", "")
    else:
        tool = event.get("toolName")
        arguments = event.get("toolArgs")
        session = event.get("sessionId", "")
        if isinstance(arguments, str):
            from ..storage.files import strict_json

            arguments = strict_json(arguments, max_bytes=256 * 1024)
    if not isinstance(tool, str) or not tool or not isinstance(arguments, dict):
        raise ValueError("The hook input is missing its tool name or arguments")
    cwd = event.get("cwd") or str(Path.cwd())
    if not isinstance(cwd, str) or not Path(cwd).expanduser().is_absolute():
        raise ValueError("The hook working directory must be absolute")
    return tool[:200], arguments, cwd, str(session)[:512]


def event_operation(event: dict, harness: str) -> Operation:
    tool, arguments, cwd, session = event_fields(event, harness)
    return Operation(harness, tool, arguments, cwd, event.get("mcp_server"), session)


def hook_output(decision: Decision, harness: str) -> dict:
    if decision.decision == "pass":
        # Do not turn an ordinary tool into "allow": that could bypass the
        # harness's own permission checks.
        return {}
    if decision.phase == "post":
        if harness == "claude":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": decision.reason,
                }
            }
        if harness == "codex":
            return {"decision": "block", "reason": decision.reason}
        if harness == "opencode":
            return {"blocked": True, "message": decision.reason}
        return {}  # Copilot does not support withholding post-tool output.
    output = {
        # Unsupported "ask" can fail open in these harnesses. A native ADR
        # approval must resolve it to pass/deny before output is emitted.
        "permissionDecision": "deny"
        if decision.decision == "ask" and harness != "claude"
        else decision.decision,
        "permissionDecisionReason": decision.reason,
    }
    if harness in ("claude", "codex"):
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", **output}}
    return output
