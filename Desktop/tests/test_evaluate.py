"""Desktop's evaluation wiring decodes each agent's event before Protection decides."""

import json

import pytest

from adr_desktop.evaluate import evaluate_operation


def snapshot(path):
    return {
        "version": 1,
        "enabled": True,
        "rules": [
            {"id": "fixture", "path": str(path), "kind": "file", "action": "block", "label": "Protected"}
        ],
        "control_paths": [],
    }


@pytest.mark.parametrize(
    ("harness", "event"),
    [
        ("claude", {"tool_name": "Read", "tool_input": {"file_path": "secret.txt"}, "session_id": "s-1"}),
        # Copilot names its fields differently and sends its arguments as a JSON string.
        ("copilot", {"toolName": "view", "toolArgs": json.dumps({"path": "secret.txt"}), "sessionId": "s-1"}),
    ],
    ids=["claude", "copilot"],
)
def test_the_decision_names_the_agents_tool_and_session(tmp_path, harness, event):
    decision = evaluate_operation(
        {**event, "cwd": str(tmp_path)}, harness, snapshot(tmp_path / "secret.txt"), state_dir=tmp_path,
    )
    assert (decision.decision, decision.reason_code) == ("deny", "protected_path")
    assert decision.tool == ("Read" if harness == "claude" else "view")
    assert decision.session_id == "s-1"
    assert decision.paths == [str(tmp_path / "secret.txt")]
