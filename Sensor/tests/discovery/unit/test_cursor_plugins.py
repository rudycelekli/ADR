"""Cursor plugins: a cache of copies and a set of marketplace clones, no records.

The layout mirrors what Cursor writes under `~/.cursor/plugins`: copies at
`cache/<owner>-<repo>/<plugin>/<commit>/` with `.cursor-plugin/plugin.json`,
clones at `marketplaces/<host>/<owner>/<repo>/<commit>/` with
`.cursor-plugin/marketplace.json`, and `local/<plugin>/`.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Kind, SourceRef
from adr_discovery.extractor.registries import read_registries
from adr_discovery.pipeline import discover

HOME = "/home/a"
BASE = f"{HOME}/.cursor/plugins"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
COPY = f"{BASE}/cache/acme-agent-plugins/formatter/{COMMIT}"
CLONE = f"{BASE}/marketplaces/github.com/acme/agent-plugins/{COMMIT}"
SKILL = "---\nname: check\n---\nbody\n"


def host(world):
    world.json(f"{COPY}/.cursor-plugin/plugin.json", {
        "name": "formatter", "version": "2.3.0", "author": {"name": "Acme", "email": "a@example.com"}})
    world.file(f"{COPY}/.cache-complete", "")
    world.file(f"{COPY}/skills/check/SKILL.md", SKILL)
    # Downloads that never finished: an empty copy, and a plugin with none.
    world.dir(f"{BASE}/cache/other-mkt/half/{'f' * 40}")
    world.dir(f"{BASE}/cache/other-mkt/none")
    world.json(f"{CLONE}/.cursor-plugin/marketplace.json", {
        "name": "acme-plugins", "owner": {"name": "Acme"}, "metadata": {"description": "x"},
        "plugins": [{"name": "formatter", "source": "cursor/plugins/formatter", "version": "2.4.0"}]})
    # The same clone also lists for another host; Cursor's own listing wins.
    world.json(f"{CLONE}/.claude-plugin/marketplace.json", {
        "name": "acme-plugins", "plugins": [{"name": "elsewhere", "source": "./claude/elsewhere"}]})
    world.json(f"{CLONE}/cursor/plugins/formatter/.cursor-plugin/plugin.json", {"name": "formatter", "version": "2.4.0"})
    world.file(f"{CLONE}/cursor/plugins/formatter/skills/check/SKILL.md", SKILL)
    world.dir(f"{BASE}/marketplaces/_staging/github.com")
    world.json(f"{BASE}/local/mine/.cursor-plugin/plugin.json", {"name": "mine", "version": "0.0.1"})
    return world


def test_cache_copies_clones_and_local_plugins_are_read(world):
    gate = host(world).gate()

    found = read_registries(gate, (HOME,))

    (market,) = [m for m in found.marketplaces if m.host == "cursor"]
    assert (market.name, market.location) == ("acme-agent-plugins", CLONE)
    assert market.source == SourceRef("git", repo="github.com/acme/agent-plugins", url="https://github.com/acme/agent-plugins")
    installs = {(i.plugin, i.marketplace, i.path, i.version, i.scope) for i in found.installs if i.host == "cursor"}
    assert installs == {
        ("formatter", "acme-agent-plugins", COPY, "2.3.0", "user"),
        ("mine", "", f"{BASE}/local/mine", "0.0.1", "local"),
    }
    assert set(found.incomplete) == {f"{BASE}/cache/other-mkt/half/{'f' * 40}", f"{BASE}/cache/other-mkt/none"}
    assert [(entry.plugin, entry.path) for entry in found.listings] == [("formatter", f"{CLONE}/cursor/plugins/formatter")]


def test_incomplete_copies_are_counted_in_coverage(world, catalog):
    snapshot = discover(host(world).gate(), catalog)

    (probe,) = [p for p in snapshot.coverage.probes if p.name == "plugin_registries" and p.status == "ran"]
    assert "2 incomplete cache copies" in probe.detail
    assert not [a for a in snapshot.assets if a.install_path and "/other-mkt/" in a.install_path]


def test_an_installed_copy_and_its_skill_carry_cursor_provenance(world, catalog):
    found = discover(host(world).gate(), catalog).assets

    (plugin,) = [a for a in found if a.install_path == COPY]
    (skill,) = [a for a in found if a.install_path == f"{COPY}/skills/check"]
    assert plugin.kind is Kind.PLUGIN and (plugin.name, plugin.version, plugin.vendor) == ("formatter", "2.3.0", "Acme")
    p = skill.provenance
    assert (p.state, p.host, p.marketplace, p.plugin, p.plugin_version, p.install_scope, p.enabled) == (
        "installed", "cursor", "acme-agent-plugins", "formatter", "2.3.0", "user", None)
    assert p.marketplace_source.repo == "github.com/acme/agent-plugins"
    assert skill.plugin_asset_id == plugin.asset_id


def test_clone_contents_are_available_and_local_plugins_have_no_marketplace(world, catalog):
    found = discover(host(world).gate(), catalog).assets

    (offered,) = [a for a in found if a.install_path == f"{CLONE}/cursor/plugins/formatter/skills/check"]
    (local,) = [a for a in found if a.install_path == f"{BASE}/local/mine"]
    assert (offered.provenance.state, offered.provenance.plugin, offered.provenance.enabled) == ("available", "formatter", None)
    assert (local.provenance.state, local.provenance.marketplace, local.provenance.install_scope) == (
        "installed", None, "local")
