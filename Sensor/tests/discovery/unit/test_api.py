"""Hosts such as ADR Desktop use Discovery only through adr_discovery.api.

This is the round trip Desktop makes: scan with the bundled catalog and
save the JSON, then read the saved coverage back to summarize and page it.
"""

from __future__ import annotations

import json

from adr_discovery import api
from adr_discovery.world.platform import FixtureProviders


def test_a_scan_through_the_api_round_trips_to_access_guidance(world):
    world.exe("/opt/homebrew/bin/claude", "2.1.234")
    world.surface("packages", [{"manager": "npm", "name": "@anthropic-ai/claude-code",
                                "version": "2.1.234", "path": "/opt/homebrew/bin/claude"}])
    world.dir("/Users/alice/.cursor").unreadable("/Users/alice/.cursor")
    gate = api.Gate(
        world.root,
        ledger=api.Ledger(),
        budget=api.Budget(max_entries=15000, reserved_walk_entries=3000, max_seconds=20),
        providers=FixtureProviders(),
        env={"HOME": "/Users/alice", "PATH": "/usr/bin:/bin"},
    )

    snapshot = api.discover(gate, api.bundled_catalog(), api.Policy(), timestamp="2026-10-14T00:00:00+00:00")
    saved = json.loads(api.to_json(snapshot))
    coverage = api.from_dict({"coverage": saved["coverage"]}).coverage

    assert [asset["catalog_id"] for asset in saved["assets"]] == ["claude-code"]
    assert api.summarize_coverage(coverage)["access"]["categories"] == ["filesystem_permissions"]
    groups = api.coverage_page(coverage, section="access")
    assert [group["root"] for group in groups["items"]] == ["/Users/alice/.cursor"]
    details = api.coverage_page(coverage, section="access", root="/Users/alice/.cursor", limit=1)
    assert details["items"][0]["path"] == "/Users/alice/.cursor"
    assert details["next_offset"] == 1
