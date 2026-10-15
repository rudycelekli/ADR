"""Plugin registries: known marketplaces, install records, enablement.

The shapes mirror what the hosts write: Claude Code's
`known_marketplaces.json`, `installed_plugins.json` (version 2), settings
`enabledPlugins` / `extraKnownMarketplaces` and marketplace manifests;
Codex's `config.toml` and plugin cache.
"""

from __future__ import annotations

from adr_discovery.contracts.records import SourceRef
from adr_discovery.extractor.registries import read_registries, repo_of, source_ref
from adr_discovery.pipeline import discover

HOME = "/home/a"
PLUGINS = f"{HOME}/.claude/plugins"
CACHE = f"{PLUGINS}/cache"


def claude_host(world):
    world.json(f"{PLUGINS}/known_marketplaces.json", {
        "acme-tools": {
            "source": {"source": "github", "repo": "acme/agent-plugins"},
            "installLocation": f"{PLUGINS}/marketplaces/acme-tools",
            "lastUpdated": "2026-01-02T03:04:05.000Z",
        },
        "team-local": {
            "source": {"source": "directory", "path": f"{HOME}/src/team-marketplace"},
            "installLocation": f"{HOME}/src/team-marketplace",
        },
    })
    world.json(f"{PLUGINS}/installed_plugins.json", {
        "version": 2,
        "plugins": {
            "linter@acme-tools": [
                {"scope": "user", "installPath": f"{CACHE}/acme-tools/linter/1.2.0",
                 "version": "1.2.0", "installedAt": "2026-01-02T03:04:05.000Z",
                 "lastUpdated": "2026-01-02T03:04:05.000Z"},
                {"scope": "project", "projectPath": f"{HOME}/proj",
                 "installPath": f"{CACHE}/acme-tools/linter/1.2.0", "version": "1.2.0"},
            ],
            "notes@team-local": [
                {"scope": "local", "projectPath": f"{HOME}/proj",
                 "installPath": f"{CACHE}/team-local/notes/0.1.0", "version": "0.1.0"},
            ],
        },
    })
    world.json(f"{CACHE}/acme-tools/linter/1.2.0/.claude-plugin/plugin.json", {"name": "linter", "version": "1.2.0"})
    world.json(f"{HOME}/.claude/settings.json", {
        "enabledPlugins": {"linter@acme-tools": True, "notes@team-local": False},
        "extraKnownMarketplaces": {
            "acme-tools": {"source": {"source": "github", "repo": "acme/agent-plugins"}},
            "extra-mkt": {"source": {"source": "git", "url": "git@git.example.com:team/mkt.git"}},
        },
    })
    world.json(f"{HOME}/proj/.claude/settings.json", {"enabledPlugins": {"linter@acme-tools": False}})
    world.json(f"{HOME}/proj/.claude/settings.local.json", {"enabledPlugins": {"notes@team-local": True}})
    world.json(f"{PLUGINS}/marketplaces/acme-tools/.claude-plugin/marketplace.json", {
        "name": "acme-tools",
        "owner": {"name": "Acme"},
        "plugins": [
            {"name": "linter", "source": "./plugins/linter", "description": "x"},
            {"name": "remote-one", "source": {"source": "url", "url": "https://user:tok@github.com/acme/remote-one.git?x=1"}},
            {"name": "subdir-one", "source": {"source": "git-subdir", "url": "https://github.com/acme/mono.git",
                                              "path": "plugins/subdir-one", "ref": "main"}},
        ],
    })
    return world


def test_claude_marketplaces_installs_and_listings_are_read(world):
    claude_host(world)
    gate = world.gate()

    found = read_registries(gate, (HOME,))

    names = {m.name: m for m in found.marketplaces}
    assert set(names) == {"acme-tools", "team-local", "extra-mkt"}
    assert names["acme-tools"].source == SourceRef("github", repo="github.com/acme/agent-plugins")
    assert names["team-local"].source == SourceRef("directory", path="~/src/team-marketplace")
    assert names["extra-mkt"].source == SourceRef("git", repo="git.example.com/team/mkt")
    assert len(found.installs) == 3
    assert sum(i.present for i in found.installs) == 2
    # Only plugins with a copy in the clone are listed; remote ones arrive on install.
    (listed,) = found.listings
    assert (listed.plugin, listed.path) == ("linter", f"{PLUGINS}/marketplaces/acme-tools/plugins/linter")
    assert [c.path for c in found.cached] == [f"{CACHE}/acme-tools/linter/1.2.0"]
    (probe,) = [p for p in gate.ledger.freeze().probes if p.name == "plugin_registries"]
    assert "3 install records (1 missing on disk)" in probe.detail


def test_enablement_follows_the_narrowest_settings_scope(world):
    claude_host(world)

    found = read_registries(world.gate(), (HOME,))
    by_scope = {(i.plugin, i.scope): i for i in found.installs}

    assert found.enabled(by_scope[("linter", "user")]) is True
    assert found.enabled(by_scope[("linter", "project")]) is False
    assert found.enabled(by_scope[("notes", "local")]) is True


def test_enablement_nothing_mentions_is_unknown(world):
    world.json(f"{PLUGINS}/installed_plugins.json", {"version": 2, "plugins": {
        "p@m": [{"scope": "user", "installPath": f"{CACHE}/m/p/1"}]}})

    found = read_registries(world.gate(), (HOME,))

    assert found.enabled(found.installs[0]) is None


def test_codex_config_and_cache(world):
    world.file(f"{HOME}/.codex/config.toml", (
        '[marketplaces.team]\nsource = "/home/a/src/team-marketplace"\nsource_type = "local"\n'
        '[plugins."linter@team"]\nenabled = true\n'
        '[plugins."gone@team"]\nenabled = false\n'
    ))
    world.json(f"{HOME}/.codex/plugins/cache/team/linter/2.0.0/.claude-plugin/plugin.json", {"name": "linter"})

    found = read_registries(world.gate(), (HOME,))

    (market,) = found.marketplaces
    assert (market.host, market.name, market.source) == ("codex", "team", SourceRef("directory", path="~/src/team-marketplace"))
    assert market.location == "/home/a/src/team-marketplace"
    (install,) = found.installs
    assert (install.plugin, install.marketplace, install.version) == ("linter", "team", "2.0.0")
    assert found.enabled(install) is True


def test_a_malformed_registry_is_a_coverage_record_not_an_empty_one(world):
    world.file(f"{PLUGINS}/installed_plugins.json", "{ not json")
    gate = world.gate()

    found = read_registries(gate, (HOME,))

    assert found.installs == ()
    degraded = [p for p in gate.ledger.freeze().probes if p.status == "degraded"]
    assert degraded and "installed_plugins.json" in degraded[0].detail


def test_a_host_without_registries_leaves_nothing(world):
    world.dir(HOME)
    gate = world.gate()

    assert read_registries(gate, (HOME,)) == read_registries(gate, ())
    assert not [p for p in gate.ledger.freeze().probes if p.name == "plugin_registries"]


def test_a_scan_records_what_the_registries_held(world, catalog):
    claude_host(world)

    snapshot = discover(world.gate(), catalog)

    assert any(p.name == "plugin_registries" for p in snapshot.coverage.probes)


def test_git_remotes_reduce_to_host_owner_repo():
    assert repo_of("git@github.com:acme/tools.git") == "github.com/acme/tools"
    assert repo_of("ssh://git@git.example.com:2222/team/tools.git") == "git.example.com/team/tools"
    assert repo_of("https://user:secret@github.com/acme/tools") == "github.com/acme/tools"
    assert repo_of("not a url") is None


def test_sources_never_carry_credentials():
    ref = source_ref({"source": "url", "url": "https://user:secret@example.com/m.json?token=t#f"}, None)

    assert "secret" not in repr(ref) and "token" not in repr(ref)
    assert ref.url == "https://example.com/m.json"
