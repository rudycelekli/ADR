"""The hook runs on every agent tool call and prompt, so its process must stay small.

The native guardian execs ``<python> -m adr_desktop hook ... --guard-protocol --phase <phase>``
and discards the core's stderr. These tests run that same command in a fresh
interpreter and read the loaded module set from ``PYTHONPROFILEIMPORTTIME``, and
time the hook module's import with ``-X importtime``.
"""

import json
import os
import statistics
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

DESKTOP = Path(__file__).resolve().parents[1]


def hook_contract():
    pyproject = tomllib.loads((DESKTOP / "pyproject.toml").read_text(encoding="utf-8"))
    [contract] = [
        contract for contract in pyproject["tool"]["importlinter"]["contracts"]
        if contract["type"] == "forbidden" and "adr_desktop.hooks" in contract["source_modules"]
    ]
    return contract


# import-linter stops the hook importing these; the process must not load them by any other route either.
FORBIDDEN = tuple(hook_contract()["forbidden_modules"])


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
    assert sorted(name for name in modules if any(within(name, prefix) for prefix in FORBIDDEN)) == []


def hook_import_ms():
    result = subprocess.run(
        [sys.executable, "-X", "importtime", "-c", "import adr_desktop.hooks"],
        capture_output=True, text=True, timeout=10, check=True,
    )
    for line in result.stderr.splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) == 3 and parts[2] == "adr_desktop.hooks":
            return int(parts[1]) / 1000
    raise AssertionError("adr_desktop.hooks is missing from the -X importtime output")


def test_hook_import_time_stays_within_budget():
    # About 27 ms locally. The ceiling is generous because CI runners are noisy; the module set
    # above is the strict check.
    hook_import_ms()  # Warm the bytecode cache.
    assert statistics.median(hook_import_ms() for _ in range(5)) < 150
