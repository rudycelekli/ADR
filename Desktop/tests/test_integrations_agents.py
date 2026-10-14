import shutil
from pathlib import Path

import pytest
from conftest import FakePluginDriver

from adr_desktop import agent_plugins
from adr_desktop.integrations import agents

HOST_ROOTS = ("CLAUDE_PLUGIN_ROOT", "PLUGIN_ROOT", "COPILOT_PLUGIN_ROOT", "ADR_PLUGIN_ROOT")


@pytest.mark.parametrize(
    ("harness", "relative"),
    [
        ("claude", ".claude/settings.json"),
        ("codex", ".codex/hooks.json"),
        ("copilot", ".copilot/hooks/adr-desktop.json"),
        ("opencode", ".config/opencode/plugins/adr-desktop.js"),
    ],
)
def test_configuration_path_stays_inside_a_given_home(tmp_path, monkeypatch, harness, relative):
    monkeypatch.setenv("CODEX_HOME", "/elsewhere/codex")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/elsewhere/config")
    assert agents.configuration_path(harness, tmp_path) == tmp_path / relative


def test_configuration_path_follows_the_agents_own_roots_without_a_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert agents.configuration_path("claude") == tmp_path / "home/.claude/settings.json"
    assert agents.configuration_path("codex") == tmp_path / "codex/hooks.json"
    assert agents.configuration_path("opencode") == tmp_path / "config/opencode/plugins/adr-desktop.js"


def test_configuration_path_rejects_an_unknown_agent(tmp_path):
    with pytest.raises(ValueError, match="Unsupported"):
        agents.configuration_path("unknown", tmp_path)


@pytest.fixture
def driver(runtime, monkeypatch):
    for name in HOST_ROOTS:
        monkeypatch.delenv(name, raising=False)
    return FakePluginDriver()


def host_copy(runtime, harness, tmp_path):
    """The agent runs its own copy of the bundle and names it in the hook's environment."""
    bundle = agents.directory(runtime.state_dir, harness) / "catalog/plugins/adr-agent"
    return Path(shutil.copytree(bundle, tmp_path / "agent-cache" / harness / "adr-agent"))


def test_plugin_root_is_the_agents_copy_of_the_connected_bundle(runtime, driver, tmp_path, monkeypatch):
    agent_plugins.connect(runtime, "claude", allow_context=True, driver=driver)
    root = host_copy(runtime, "claude", tmp_path)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    assert agents.plugin_root(runtime.state_dir, "claude") == root.resolve()


def test_plugin_root_rejects_a_relative_or_edited_copy(runtime, driver, tmp_path, monkeypatch):
    agent_plugins.connect(runtime, "claude", allow_context=True, driver=driver)
    root = host_copy(runtime, "claude", tmp_path)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "agent-cache/claude/adr-agent")
    assert agents.plugin_root(runtime.state_dir, "claude") is None
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    (root / "hooks/hooks.json").write_text("{}")
    assert agents.plugin_root(runtime.state_dir, "claude") is None


def test_plugin_root_needs_a_configured_connection(runtime, driver, tmp_path, monkeypatch):
    assert agents.plugin_root(runtime.state_dir, "codex") is None
    agent_plugins.connect(runtime, "claude", allow_context=True, driver=driver)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(host_copy(runtime, "claude", tmp_path)))
    agent_plugins.disconnect(runtime, "claude", driver=driver)
    assert agents.plugin_root(runtime.state_dir, "claude") is None


def test_opencode_plugin_root_needs_adrs_plugin_file_unchanged(runtime, driver, tmp_path, monkeypatch):
    agent_plugins.connect(runtime, "opencode", allow_context=True, driver=driver)
    root = host_copy(runtime, "opencode", tmp_path)
    monkeypatch.setenv("ADR_PLUGIN_ROOT", str(root))
    assert agents.plugin_root(runtime.state_dir, "opencode") == root.resolve()
    plugin = agents.configuration_path("opencode")
    plugin.write_text(plugin.read_text() + "\n// edited\n")
    assert agents.plugin_root(runtime.state_dir, "opencode") is None
