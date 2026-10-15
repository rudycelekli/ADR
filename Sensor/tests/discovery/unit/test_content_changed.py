"""`content_changed`: an asset that kept its id but not its bytes.

A plugin update can rewrite a skill without touching its version, and the
version string is whatever the publisher wrote. The hash is not.
"""

from __future__ import annotations

from adr_discovery.contracts.records import Asset, Kind
from adr_discovery.contracts.snapshot import Snapshot
from adr_discovery.pipeline import discover
from adr_discovery.reporter import diff

A, B = "a" * 64, "b" * 64


def snapshot(*assets):
    return Snapshot(hostname="host-a", username="alice", platform="linux",
                    timestamp="2026-10-12T00:00:00+00:00", assets=tuple(assets))


def skill(sha=None, version="1.0", content=None):
    return Asset(asset_id="id-s", kind=Kind.SKILL, name="s", identity="skill:/s",
                 version=version, skill_sha256=sha, content_hash=content)


def test_a_new_folder_hash_is_a_content_change():
    delta = diff(snapshot(skill(A)), snapshot(skill(B)))

    assert [(c.kind, c.detail) for c in delta.changes] == [
        ("content_changed", f"skill_sha256 {A[:12]} -> {B[:12]}")
    ]


def test_a_new_file_hash_is_a_content_change():
    delta = diff(snapshot(skill(content=A)), snapshot(skill(content=B)))

    assert [c.kind for c in delta.changes] == ["content_changed"]


def test_a_hash_that_could_not_be_computed_any_more_is_reported():
    delta = diff(snapshot(skill(A)), snapshot(skill(None)))

    assert [c.detail for c in delta.of("content_changed")] == [f"skill_sha256 {A[:12]} -> none"]


def test_version_and_content_are_separate_changes():
    delta = diff(snapshot(skill(A, "1.0")), snapshot(skill(B, "1.1")))

    assert sorted(c.kind for c in delta.changes) == ["content_changed", "version_changed"]


def test_unchanged_content_is_no_change():
    assert diff(snapshot(skill(A)), snapshot(skill(A))).is_empty


def test_editing_a_file_beside_skill_md_is_seen_end_to_end(world, catalog):
    world.dir("/home/a")
    world.file("/home/a/.claude/skills/s/SKILL.md", "---\nname: s\n---\nbody\n")
    world.file("/home/a/.claude/skills/s/scripts/run.sh", "echo one\n")
    before = discover(world.gate(), catalog)
    again = discover(world.gate(), catalog)
    world.file("/home/a/.claude/skills/s/scripts/run.sh", "echo two\n")
    after = discover(world.gate(), catalog)

    assert diff(before, again).of("content_changed") == ()
    changed = diff(before, after).of("content_changed")
    assert [c.name for c in changed] == ["s"]
    assert changed[0].detail.startswith("skill_sha256 ")
