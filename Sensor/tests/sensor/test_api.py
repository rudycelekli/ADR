"""Hosts such as ADR Desktop use Sensor only through adr_sensor.api."""

import json
from datetime import datetime, timezone

from adr_sensor import api


def test_the_observer_ingests_a_claude_session_with_its_diagnostics(tmp_path):
    projects = tmp_path / "projects"
    projects.mkdir()
    timestamp = datetime.now(timezone.utc).isoformat()
    records = [
        {"type": role, "sessionId": "synthetic", "timestamp": timestamp, "cwd": "/workspace",
         "message": {"content": text}}
        for role, text in [("user", "Check the fixture"), ("assistant", "The fixture was checked.")]
    ]
    (projects / "session.jsonl").write_text("".join(json.dumps(record) + "\n" for record in records))
    observer = api.AgentObserver(output_dir=tmp_path / "output", max_age_days=14)
    observer.SOURCES = (("claude", "Claude Code"),)
    observer.claude_parser.base_path = projects

    entries, _ = observer.ingest_all()

    assert [entry.to_dict()["session_id"] for entry in entries] == ["claude_synthetic"]
    assert [record["source"] for record in observer.get_diagnostic_records()] == ["claude"]


def test_codex_session_context_keeps_only_explicit_lineage():
    context = api.codex_session_context({"id": "child", "forked_from_id": "origin", "name": "Synthetic"})

    assert context == {
        "session_kind": "fork", "forked_from_session_id": "codex_origin", "session_title": "Synthetic",
    }
