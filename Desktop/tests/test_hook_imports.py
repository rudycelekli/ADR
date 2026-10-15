"""The hook runs on every agent tool call and prompt, so its process must stay small.

The native guardian execs ``<python> -m adr_desktop hook ... --guard-protocol --phase <phase>``
and discards the core's stderr. These tests run that same command in a fresh
interpreter and read the loaded module set from ``PYTHONPROFILEIMPORTTIME``.
"""

import json
import os
import subprocess
import sys

import pytest

FORBIDDEN = (
    "fastapi",
    "uvicorn",
    "starlette",
    "adr_desktop.runtime",
    "adr_desktop.api",
    "adr_desktop.store",
    "adr_desktop.storage.database",
    "adr_desktop.detection.review",
    "adr_desktop.security_reviews",
    "adr_sensor",
    "adr_discovery",
)

# Forbidden modules the hook still loads, by phase. None are left. These
# lists only shrink: delete an entry once the hook stops loading it.
KNOWN_LOADS = {"pre": (), "prompt": ()}


def loaded_modules(stderr):
    return {
        line.rsplit("|", 1)[1].strip()
        for line in stderr.splitlines()
        if line.startswith("import time:") and not line.rstrip().endswith("| imported package")
    }


def within(name, prefix):
    return name == prefix or name.startswith(prefix + ".")


@pytest.mark.parametrize(
    ("phase", "event", "decision"),
    [
        ("pre", {"tool_name": "Bash", "tool_input": {"command": "ls"}}, "pass"),
        ("pre", {"tool_name": "Read", "tool_input": {"file_path": "/workspace/notes.md"}}, "pass"),
        # No app is listening, so the prompt check fails closed.
        ("prompt", {"hook_event_name": "UserPromptSubmit", "prompt": "Summarize the notes"}, "deny"),
    ],
)
def test_hook_process_loads_no_forbidden_module(runtime, phase, event, decision):
    command = [
        sys.executable, "-m", "adr_desktop", "hook", "--harness", "claude",
        "--state-dir", str(runtime.state_dir), "--guard-protocol", "--phase", phase,
    ]
    result = subprocess.run(
        command,
        input=json.dumps({"cwd": "/workspace", "session_id": "synthetic", **event}),
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "PYTHONPROFILEIMPORTTIME": "1"},
    )
    assert (result.returncode, result.stdout) == (0, decision + "\n")
    modules = loaded_modules(result.stderr)
    assert ("adr_desktop.prompt_guard" if phase == "prompt" else "adr_desktop.hooks") in modules
    known = KNOWN_LOADS[phase]
    loaded = sorted(name for name in modules if any(within(name, prefix) for prefix in FORBIDDEN))
    assert [name for name in loaded if not any(within(name, prefix) for prefix in known)] == []
    still_loaded = [prefix for prefix in known if any(within(name, prefix) for name in loaded)]
    assert still_loaded == list(known), "Remove the entries the hook no longer loads"
