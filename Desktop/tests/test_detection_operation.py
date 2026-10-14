"""Desktop decodes an agent event into the Operation that detection reads."""

import json

import pytest

from adr_desktop.detection.contracts import Operation
from adr_desktop.detection.operation import SHELL_TOOLS, literal_shell_files
from adr_desktop.integrations.events import event_operation


@pytest.mark.parametrize(
    ("harness", "event"),
    [
        ("claude", {"tool_name": "Read", "tool_input": {"file_path": "notes.md"}}),
        # Copilot sends its arguments as a JSON string.
        ("copilot", {"toolName": "Read", "toolArgs": json.dumps({"file_path": "notes.md"})}),
    ],
    ids=["claude", "copilot"],
)
def test_an_agent_event_becomes_the_operation_detection_reads(tmp_path, harness, event):
    operation = event_operation({**event, "cwd": str(tmp_path)}, harness)
    assert operation == Operation(
        harness=harness, tool="Read", arguments={"file_path": "notes.md"}, cwd=str(tmp_path),
    )


def test_detection_finds_the_file_a_wrapped_shell_operation_reads(tmp_path):
    (tmp_path / "work").mkdir()
    event = {"tool_name": "exec_command", "cwd": str(tmp_path),
             "tool_input": {"cmd": "bash -lc 'cat notes.md'", "workdir": "work"}}
    operation = event_operation(event, "codex")
    assert operation.tool in SHELL_TOOLS
    assert literal_shell_files(operation.arguments, operation.cwd) == [tmp_path / "work" / "notes.md"]
