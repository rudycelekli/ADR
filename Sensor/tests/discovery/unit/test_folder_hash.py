"""`skill_sha256` is the folder hash of the skill directory.

The expected digests below were produced by an independent implementation
of the same definition; they pin the byte layout, not this code's opinion
of it. A change to any of them is a change of identity for every skill.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from adr_discovery.contracts.records import Kind
from adr_discovery.pipeline import discover
from adr_discovery.world.budget import Budget

BASIC = [
    ("SKILL.md", "---\nname: basic\n---\nbody\n", 0o644),
    ("scripts/run.sh", "#!/bin/sh\necho hi\n", 0o755),
    ("references/notes.md", "notes\n", 0o644),
]


def variant(changes):
    files = {rel: (body, mode) for rel, body, mode in BASIC}
    files.update(changes)
    return [(rel, body, mode) for rel, (body, mode) in files.items()]


VECTORS = {
    "basic": BASIC,
    "changed_file": variant({"references/notes.md": ("notes!\n", 0o644)}),
    "added_file": variant({"extra.txt": ("x", 0o644)}),
    "chmod_exec": variant({"references/notes.md": ("notes\n", 0o755)}),
    "nested": [("SKILL.md", "---\nname: n\n---\n", 0o644), ("a/b/c/d.txt", "deep\n", 0o600)],
    # '-' < '.' < '/' and 'B' < 'a' byte-wise; a non-ASCII name sorts by its UTF-8 bytes.
    "byte_order": [("B", "1", 0o644), ("a-b", "2", 0o644), ("a.b", "3", 0o644),
                   ("a/b", "4", 0o644), ("ä", "5", 0o644)],
    "empty": [],
}

EXPECTED = {
    "basic": "43b6a6ccd05d30187a02a4882ae3854577abd83cb2e759f02267a113a467c12d",
    "changed_file": "ed16cb97eb3e6dfe1a55fc4cd1d6c24e5bfc8c58f1108a1fd2dee5342f29b033",
    "added_file": "d7f6b98201030687d4961f5b73ad527d04ddce1bcad5c2070d01e99d5f9cf69a",
    "chmod_exec": "0efc0a807264f0dd518a8fe41aa62e38ca382c8f6589187631ce35b4ac5dad2f",
    "nested": "5964d781a9055d5c72570808521fb2444ef52d84015f6e5db32737bb034d4b75",
    "byte_order": "93cb6b93d59b2855498256f38cd5379c06dc21324b5ce0ce5978d3b81958066c",
    "empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def build(world, root: str, files) -> str:
    world.dir(root)
    for rel, body, mode in files:
        world.file(f"{root}/{rel}", body)
        os.chmod(world.root + f"{root}/{rel}", mode)
    return root


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_vectors(world, name):
    root = build(world, f"/t/{name}", VECTORS[name])

    digest = world.gate().hash_tree(root)

    assert digest.ok
    assert digest.value.sha256 == EXPECTED[name]
    assert digest.value.files == len(VECTORS[name])


def test_every_change_moves_the_hash():
    assert len(set(EXPECTED.values())) == len(EXPECTED)


def test_identical_trees_hash_equal_wherever_they_sit(world):
    gate = world.gate()

    one = gate.hash_tree(build(world, "/a/skill", BASIC))
    two = gate.hash_tree(build(world, "/b/elsewhere/other-name", BASIC))

    assert one.value.sha256 == two.value.sha256 == EXPECTED["basic"]


def test_symlinks_and_empty_directories_are_not_content(world):
    root = build(world, "/t/skill", BASIC)
    world.symlink("/t/skill/link.md", "/t/skill/SKILL.md")
    world.symlink("/t/skill/dirlink", "/t/skill/scripts")
    world.symlink("/t/skill/dangling", "/t/nowhere")
    world.dir("/t/skill/emptydir")

    assert world.gate().hash_tree(root).value.sha256 == EXPECTED["basic"]


def test_a_root_reached_through_a_link_hashes_its_target(world):
    build(world, "/real/skill", BASIC)
    world.symlink("/home/a/.claude/skills/skill", "/real/skill")

    assert world.gate().hash_tree("/home/a/.claude/skills/skill").value.sha256 == EXPECTED["basic"]


# ------------------------------------------------------------------ caps


def _refused(world, gate, root, reason):
    digest = gate.hash_tree(root)
    assert not digest.ok and digest.reason == reason
    hits = [b for b in gate.ledger.freeze().boundaries_hit if b.boundary == "no_folder_hash"]
    assert [h.path for h in hits] == [root]
    assert hits[0].detail.startswith(reason)


def test_too_many_files_gets_no_hash(world):
    root = build(world, "/t/skill", BASIC)
    _refused(world, world.gate(budget=Budget(max_tree_files=2)), root, "too_many_files")


def test_a_file_over_the_cap_gets_no_hash(world):
    root = build(world, "/t/skill", BASIC)
    _refused(world, world.gate(budget=Budget(max_tree_file_bytes=10)), root, "file_too_large")


def test_a_tree_over_the_cap_gets_no_hash(world):
    root = build(world, "/t/skill", BASIC)
    _refused(world, world.gate(budget=Budget(max_tree_bytes=30)), root, "tree_too_large")


def test_an_unreadable_file_gets_no_hash_not_a_partial_one(world):
    root = build(world, "/t/skill", BASIC)
    os.chmod(world.root + "/t/skill/references/notes.md", 0o000)
    world._restore.append(world.root + "/t/skill/references/notes.md")
    if os.access(world.root + "/t/skill/references/notes.md", os.R_OK):
        pytest.skip("running with privileges that ignore file modes")

    _refused(world, world.gate(), root, "unreadable_member")


def test_hashing_has_its_own_budget(world):
    root = build(world, "/t/skill", BASIC)
    total = sum(len(body) for _, body, _ in BASIC)
    gate = world.gate(budget=Budget(max_entries=1, max_hash_bytes=total))
    gate.budget.take_entries(1)  # the sweep has spent the entry ceiling

    assert gate.hash_tree(root).value.sha256 == EXPECTED["basic"]
    _refused(world, gate, build(world, "/t/again", BASIC), "hash_budget_exhausted")


# ------------------------------------------------------------- pipeline


def test_skill_sha256_is_the_folder_hash(world, catalog):
    world.dir("/home/a")
    build(world, "/home/a/.claude/skills/basic", BASIC)

    snapshot = discover(world.gate(), catalog)

    skill = next(a for a in snapshot.assets if a.kind is Kind.SKILL)
    assert skill.skill_sha256 == EXPECTED["basic"]


def test_a_payload_beside_skill_md_changes_the_skill_identity(world, catalog):
    world.dir("/home/a")
    build(world, "/home/a/.claude/skills/basic", VECTORS["changed_file"])

    snapshot = discover(world.gate(), catalog)

    skill = next(a for a in snapshot.assets if a.kind is Kind.SKILL)
    assert skill.skill_sha256 == EXPECTED["changed_file"]


def test_a_skill_md_only_skill_hashes_its_one_file(world, catalog):
    body = "---\nname: one\n---\nbody\n"
    world.dir("/home/a")
    world.file("/home/a/.claude/skills/one/SKILL.md", body)

    snapshot = discover(world.gate(), catalog)

    skill = next(a for a in snapshot.assets if a.kind is Kind.SKILL)
    assert skill.skill_sha256 == hashlib.sha256(b"SKILL.md\n0\n" + body.encode()).hexdigest()
