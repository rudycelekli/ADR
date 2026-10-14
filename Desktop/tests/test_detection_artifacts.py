"""Detection's artifact identity and installed-item check, with a fake AgentConfig and no Desktop runtime."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from adr_desktop.detection.contracts import Operation
from adr_desktop.detection.inline.artifacts import identify_operation
from adr_desktop.detection.inline.feed.api_v1 import BUNDLED_FEED_ID, compose_generation
from adr_desktop.detection.inline.installed import MAX_SCAN_PROJECTS, scan_installed


class Agents:
    """Fake AgentConfig: every agent keeps its hook configuration in its own folder under one root."""

    def __init__(self, root):
        self.root = root

    def configuration_path(self, harness):
        return self.root / harness / "hooks.json"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    for key in tuple(os.environ):
        if key.lower().startswith(("pip_", "npm_config_", "uv_", "xdg_")) or key == "VIRTUAL_ENV":
            monkeypatch.delenv(key)
    # Codex's own variable points elsewhere: identity must ask AgentConfig instead.
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "unused-codex-home"))
    return home


@pytest.fixture
def agents(tmp_path):
    return Agents(tmp_path / "agent-config")


@pytest.fixture
def project(tmp_path):
    path = tmp_path / "project"
    path.mkdir()
    return path


def subjects(evidence):
    return [candidate.subject for candidate in evidence.candidates]


def test_codex_mcp_server_is_found_in_the_folder_agent_config_names(agents, project):
    config = agents.root / "codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers.fixture]\nurl="https://fixture.example.invalid/mcp"\n')
    operation = Operation(harness="codex", tool="mcp__fixture__lookup", arguments={}, cwd=str(project))
    evidence = identify_operation(operation, agents)
    assert subjects(evidence) == [{"kind": "mcp_endpoint", "url": "https://fixture.example.invalid/mcp"}]
    assert evidence.candidates[0].location == str(config)


def test_the_mcp_server_an_operation_names_settles_two_servers_with_one_alias(agents, project, isolated_home):
    def servers(url):
        return json.dumps({"mcpServers": {"fixture": {"url": url}}})

    (project / ".mcp.json").write_text(servers("https://project.example.invalid/mcp"))
    (isolated_home / ".claude.json").write_text(servers("https://user.example.invalid/mcp"))
    fields = {"harness": "claude", "tool": "mcp__fixture__lookup", "arguments": {}, "cwd": str(project)}
    unnamed = identify_operation(Operation(**fields), agents)
    assert not unnamed.candidates and unnamed.unresolved == ["mcp_definition_conflict"]
    named = Operation(**fields, mcp_server={"name": "fixture", "source": "user"})
    assert subjects(identify_operation(named, agents)) == [
        {"kind": "mcp_endpoint", "url": "https://user.example.invalid/mcp"},
    ]


BODY = b"---\nname: harmless-fixture\n---\nInert local test; never execute.\n"
ENDPOINT = "https://fixture-server.invalid/mcp"
CHECKED_AT = "2026-10-14T09:00:00Z"


@pytest.fixture
def generation():
    skill = {"sha256": hashlib.sha256(BODY).hexdigest()}
    indicators = [
        {"id": "fixture-skill", "kind": "skill_sha256", "target": skill},
        {"id": "fixture-endpoint", "kind": "mcp_endpoint", "target": {"url": ENDPOINT}},
    ]
    return compose_generation({
        "schema_version": 1, "feed_id": BUNDLED_FEED_ID, "revision": 1,
        "published_at": "2026-10-05T00:00:00Z",
        "indicators": [{
            **indicator, "status": "active", "summary": "Harmless fixture, not a real malicious artifact.",
            "references": ["https://example.invalid/disclosure"],
        } for indicator in indicators],
    })


def findings(result):
    return sorted((item["kind"], item["location"], item["label"]) for item in result["findings"])


def test_installed_check_matches_project_skills_and_agent_mcp_servers_against_the_feed(
    agents, project, generation,
):
    skill = project / ".claude/skills/harmless/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_bytes(BODY)
    config = agents.root / "codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(f'[mcp_servers.fixture]\nurl="{ENDPOINT}"\n')
    result = scan_installed(generation, {}, [str(project), "relative/project"], agents, checked_at=CHECKED_AT)
    assert (result["state"], result["checked_at"], result["generation"]) == (
        "complete", CHECKED_AT, generation["digest"],
    )
    assert findings(result) == [
        ("mcp_endpoint", str(config), "fixture · codex"),
        ("skill_sha256", str(skill.resolve()), "harmless"),
    ]
    assert skill.read_bytes() == BODY


def test_installed_check_links_a_finding_to_the_inventory_item_it_came_from(tmp_path, agents, generation):
    folder = tmp_path / "installed-elsewhere" / "harmless"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_bytes(BODY)
    inventory = {"assets": [{"asset_id": "fixture-asset", "kind": "skill", "install_path": str(folder)}]}
    result = scan_installed(generation, inventory, [], agents, checked_at=CHECKED_AT)
    assert [(item["label"], item["inventory_asset_id"]) for item in result["findings"]] == [
        ("harmless", "fixture-asset"),
    ]


def test_an_installed_check_that_skips_projects_is_partial_not_clean(tmp_path, agents, generation):
    projects = [str(tmp_path / f"project-{number}") for number in range(MAX_SCAN_PROJECTS)]
    result = scan_installed(generation, {}, projects, agents, checked_at=CHECKED_AT)
    assert result["state"] == "partial"
    assert {"reason": "project_limit", "count": 1} in result["issues"]
