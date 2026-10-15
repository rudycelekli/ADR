"""Provenance: what the host's plugin registries say about each asset."""

from __future__ import annotations

import json

from adr_discovery.contracts.records import Kind, SourceRef
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_json
from adr_discovery.reporter.snapshot import from_dict

HOME = "/home/a"
PLUGINS = f"{HOME}/.claude/plugins"
CACHE = f"{PLUGINS}/cache"
CLONE = f"{PLUGINS}/marketplaces/acme-tools"
INSTALLED = f"{CACHE}/acme-tools/linter/1.2.0"
STALE = f"{CACHE}/acme-tools/linter/1.1.0"
SKILL = "---\nname: lint\n---\nbody\n"


def host(world):
    world.json(f"{PLUGINS}/known_marketplaces.json", {
        "acme-tools": {"source": {"source": "github", "repo": "acme/agent-plugins"}, "installLocation": CLONE},
    })
    world.json(f"{PLUGINS}/installed_plugins.json", {"version": 2, "plugins": {
        "linter@acme-tools": [
            {"scope": "project", "projectPath": f"{HOME}/proj", "installPath": INSTALLED,
             "version": "1.2.0", "installedAt": "2026-02-01T00:00:00.000Z"},
            {"scope": "user", "installPath": INSTALLED, "version": "1.2.0",
             "installedAt": "2026-01-01T00:00:00.000Z"},
        ],
        "gone@acme-tools": [{"scope": "user", "installPath": f"{CACHE}/acme-tools/gone/9.9.9"}],
    }})
    world.json(f"{HOME}/.claude/settings.json", {"enabledPlugins": {"linter@acme-tools": False}})
    world.json(f"{HOME}/proj/.claude/settings.json", {"enabledPlugins": {"linter@acme-tools": True}})
    world.json(f"{INSTALLED}/.claude-plugin/plugin.json", {"name": "linter", "version": "1.2.0"})
    world.file(f"{INSTALLED}/skills/lint/SKILL.md", SKILL)
    world.file(f"{STALE}/skills/lint/SKILL.md", SKILL)
    world.json(f"{CLONE}/.claude-plugin/marketplace.json", {"name": "acme-tools", "plugins": [
        {"name": "linter", "source": "./plugins/linter"}]})
    world.json(f"{CLONE}/plugins/linter/.claude-plugin/plugin.json", {"name": "linter", "version": "1.3.0"})
    world.file(f"{CLONE}/plugins/linter/skills/lint/SKILL.md", SKILL)
    return world


def assets(world, catalog):
    return discover(world.gate(), catalog).assets


def at(found, path):
    (asset,) = [a for a in found if a.install_path == path]
    return asset


def test_an_installed_plugin_and_its_skill_are_installed(world, catalog):
    found = assets(host(world), catalog)

    plugin = at(found, INSTALLED)
    skill = at(found, f"{INSTALLED}/skills/lint")

    assert plugin.kind is Kind.PLUGIN and plugin.version == "1.2.0"
    p = skill.provenance
    assert (p.state, p.host, p.marketplace, p.plugin, p.plugin_version) == (
        "installed", "claude", "acme-tools", "linter", "1.2.0")
    assert p.marketplace_source == SourceRef("github", repo="github.com/acme/agent-plugins")
    # Broadest scope, earliest install, on in the project that installed it.
    assert (p.install_scope, p.installed_at, p.enabled) == ("user", "2026-01-01T00:00:00.000Z", True)
    assert skill.plugin_asset_id == plugin.asset_id
    assert plugin.provenance == p and plugin.plugin_asset_id is None


def test_a_marketplace_clone_is_available_and_a_cached_leftover_is_stale(world, catalog):
    found = assets(host(world), catalog)

    clone = at(found, f"{CLONE}/plugins/linter/skills/lint")
    stale = at(found, f"{STALE}/skills/lint")

    assert (clone.provenance.state, clone.provenance.plugin, clone.provenance.enabled) == ("available", "linter", None)
    assert clone.plugin_asset_id == at(found, f"{CLONE}/plugins/linter").asset_id
    assert (stale.provenance.state, stale.provenance.plugin_version) == ("stale", "1.1.0")


def test_a_plugin_no_registry_names_is_unregistered(world, catalog):
    world.json(f"{HOME}/tools/plugins/side/.claude-plugin/plugin.json", {"name": "side", "version": "0.1"})
    world.file(f"{HOME}/tools/plugins/side/skills/s/SKILL.md", SKILL)

    found = assets(world, catalog)

    skill = at(found, f"{HOME}/tools/plugins/side/skills/s")
    assert (skill.provenance.state, skill.provenance.plugin, skill.provenance.marketplace) == ("unregistered", "side", None)
    assert skill.plugin_asset_id == at(found, f"{HOME}/tools/plugins/side").asset_id


def test_an_unlisted_clone_still_declares_its_marketplace(world, catalog):
    clone = f"{HOME}/.codex/.tmp/plugins"
    world.json(f"{clone}/.agents/plugins/marketplace.json", {"name": "curated", "plugins": []})
    world.json(f"{clone}/plugins/one/.codex-plugin/plugin.json", {"name": "one", "version": "2.0.0"})
    world.file(f"{clone}/plugins/one/skills/s/SKILL.md", SKILL)

    skill = at(assets(world, catalog), f"{clone}/plugins/one/skills/s")

    assert (skill.provenance.state, skill.provenance.marketplace, skill.provenance.plugin) == ("available", "curated", "one")


def test_codex_cache_plugins_are_installed_with_their_toggle(world, catalog):
    world.file(f"{HOME}/.codex/config.toml", '[plugins."linter@team"]\nenabled = false\n')
    root = f"{HOME}/.codex/plugins/cache/team/linter/2.0.0"
    world.json(f"{root}/.claude-plugin/plugin.json", {"name": "linter", "version": "2.0.0"})
    world.file(f"{root}/skills/lint/SKILL.md", SKILL)

    skill = at(assets(world, catalog), f"{root}/skills/lint")

    assert (skill.provenance.host, skill.provenance.state, skill.provenance.enabled) == ("codex", "installed", False)


def test_assets_outside_plugins_carry_none(world, catalog):
    world.file(f"{HOME}/.claude/skills/own/SKILL.md", SKILL)

    skill = at(assets(host(world), catalog), f"{HOME}/.claude/skills/own")

    assert skill.provenance is None and skill.plugin_asset_id is None


def test_provenance_never_changes_an_asset_id(world, catalog):
    world.file(f"{HOME}/.claude/skills/own/SKILL.md", SKILL)
    world.file(f"{INSTALLED}/skills/lint/SKILL.md", SKILL)
    before = {a.install_path: a.asset_id for a in assets(world, catalog)}

    host(world)
    after = {a.install_path: a.asset_id for a in assets(world, catalog)}

    assert all(after[path] == asset_id for path, asset_id in before.items())


def test_provenance_survives_a_round_trip(world, catalog):
    snapshot = discover(host(world).gate(), catalog)

    back = from_dict(json.loads(to_json(snapshot)))

    assert [a.provenance for a in back.assets] == [a.provenance for a in snapshot.assets]
    assert [a.plugin_asset_id for a in back.assets] == [a.plugin_asset_id for a in snapshot.assets]
