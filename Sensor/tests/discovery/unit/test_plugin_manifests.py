"""Plugin manifests name and version a plugin, and nothing else is read."""

from __future__ import annotations

from adr_discovery.contracts.records import Candidate, Kind
from adr_discovery.extractor import extract
from adr_discovery.pipeline import discover

MANIFEST = {
    "name": "release-tools",
    "version": "1.4.0",
    "description": "internal release checklist for the billing service",
    "author": {"name": "Example Org", "email": "someone@example.com"},
    "homepage": "https://example.com/private",
}


def read(world, path):
    gate = world.gate()
    return gate, extract(gate, Candidate(kind="marker_dir", path=path, source="sweep"))


def test_a_claude_plugin_manifest_names_and_versions_the_plugin(world):
    world.json("/home/a/.claude/plugins/rt/.claude-plugin/plugin.json", MANIFEST)

    _, result = read(world, "/home/a/.claude/plugins")
    (plugin,) = result.declarations

    assert plugin.name == "release-tools"
    assert plugin.raw["version"] == "1.4.0"
    assert plugin.raw["vendor"] == "Example Org"
    blob = repr(plugin)
    assert "billing" not in blob and "someone@" not in blob and "private" not in blob


def test_codex_and_bare_manifests_count_too(world):
    world.json("/home/a/m/plugins/one/.codex-plugin/plugin.json", {"name": "one", "version": "2.0.0"})
    world.json("/home/a/m/plugins/two/plugin.json", {"name": "two", "author": "Solo Dev"})

    _, result = read(world, "/home/a/m/plugins")
    by_name = {d.name: d for d in result.declarations}

    assert by_name["one"].raw["version"] == "2.0.0"
    assert by_name["two"].raw["vendor"] == "Solo Dev" and "version" not in by_name["two"].raw


def test_a_malformed_manifest_keeps_the_plugin_and_records_why(world):
    world.file("/home/a/.claude/plugins/broken/.claude-plugin/plugin.json", "{not json")
    world.json("/home/a/.claude/plugins/ok/.claude-plugin/plugin.json", {"name": "ok"})

    gate, result = read(world, "/home/a/.claude/plugins")
    by_name = {d.name: d for d in result.declarations}

    assert result.declared == 2 and not result.errors
    assert by_name["broken"].raw["flags"] == ("malformed",)
    probes = [p for p in gate.ledger.freeze().probes if p.name == "plugin_manifest"]
    assert probes and probes[0].status == "degraded" and "broken" in probes[0].detail


def test_the_plugin_asset_carries_version_and_vendor(world, catalog):
    world.json("/home/a/.claude/plugins/rt/.claude-plugin/plugin.json", MANIFEST)

    (plugin,) = [a for a in discover(world.gate(), catalog).assets if a.kind is Kind.PLUGIN]

    assert (plugin.name, plugin.version, plugin.vendor) == ("release-tools", "1.4.0", "Example Org")
    assert "someone@example.com" not in repr(plugin)
