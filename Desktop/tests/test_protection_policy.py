"""Protection applies the file rules to the Operation Desktop decoded; it never reads an agent's event."""

from adr_desktop.detection.contracts import Operation
from adr_desktop.protection.policy import evaluate


def test_protection_decides_from_the_operation_alone(tmp_path):
    snapshot = {
        "version": 1,
        "enabled": True,
        "rules": [{"id": "fixture", "path": str(tmp_path / "secret.txt"), "kind": "file",
                   "action": "block", "label": "Protected"}],
        "control_paths": [],
    }
    operation = Operation(
        harness="codex", tool="exec_command", arguments={"cmd": "cat secret.txt"}, cwd=str(tmp_path),
        session_id="s-1",
    )
    decision = evaluate(operation, snapshot)
    assert (decision.decision, decision.reason_code) == ("deny", "protected_path")
    assert decision.rule_id == "fixture"
    assert decision.paths == [str(tmp_path / "secret.txt")]
    assert (decision.tool, decision.session_id) == ("exec_command", "s-1")
