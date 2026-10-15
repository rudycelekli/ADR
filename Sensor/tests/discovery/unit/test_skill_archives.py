"""Skill archives: deterministic, content-addressed, verifiable by hash."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile

import pytest

from adr_discovery import cli
from adr_discovery.archive import ArchiveError, Archiver, archive_skill, zip_content_sha256
from adr_discovery.contracts.records import Kind
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_json
from adr_discovery.reporter.snapshot import from_dict
from adr_discovery.world.store import ArchiveStore

BASIC = [
    ("SKILL.md", "---\nname: basic\n---\nbody\n", 0o644),
    ("scripts/run.sh", "#!/bin/sh\necho hi\n", 0o755),
    ("references/notes.md", "notes\n", 0o644),
]
#: The folder hash of BASIC, as pinned in test_folder_hash.
EXPECTED = {"basic": "43b6a6ccd05d30187a02a4882ae3854577abd83cb2e759f02267a113a467c12d"}


def build(world, root: str, files) -> str:
    world.dir(root)
    for rel, body, mode in files:
        world.file(f"{root}/{rel}", body)
        os.chmod(world.root + f"{root}/{rel}", mode)
    return root


SKILL = "/home/a/.claude/skills/basic"


def skill(world, root=SKILL, files=BASIC):
    world.dir("/home/a")
    return build(world, root, files)


def archive(world, dest, **kwargs):
    result = archive_skill(SKILL, str(dest), gate=world.gate(), now="2026-10-12T00:00:00+00:00", **kwargs)
    assert result.ok, result
    return result.value


def read(path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def index_of(dest):
    with open(os.path.join(dest, "index.jsonl"), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


# --------------------------------------------------------------- format


def test_the_archive_is_named_by_and_reproduces_the_folder_hash(world, tmp_path):
    skill(world)

    archived = archive(world, tmp_path / "out")

    assert archived.skill_sha256 == EXPECTED["basic"]
    assert os.path.basename(archived.path) == f"{EXPECTED['basic']}.zip"
    assert zip_content_sha256(read(archived.path)) == EXPECTED["basic"]
    assert (archived.files, archived.bytes) == (3, sum(len(b) for _, b, _ in BASIC))


def test_the_archive_is_deterministic(world, tmp_path):
    skill(world)

    one = archive(world, tmp_path / "one")
    os.utime(world.root + SKILL + "/SKILL.md", (1, 1))  # mtimes are not content
    two = archive(world, tmp_path / "two")

    assert read(one.path) == read(two.path)
    assert one.archive_sha256 == two.archive_sha256


def test_entries_are_relative_sorted_dated_and_keep_the_execute_bit(world, tmp_path):
    skill(world)
    world.symlink(SKILL + "/link.md", SKILL + "/SKILL.md")
    world.dir(SKILL + "/emptydir")

    with zipfile.ZipFile(archive(world, tmp_path / "out").path) as zf:
        infos = zf.infolist()

    assert [i.filename for i in infos] == ["SKILL.md", "references/notes.md", "scripts/run.sh"]
    assert {i.date_time for i in infos} == {(1980, 1, 1, 0, 0, 0)}
    modes = {i.filename: i.external_attr >> 16 for i in infos}
    assert stat.S_IMODE(modes["scripts/run.sh"]) == 0o755
    assert stat.S_IMODE(modes["SKILL.md"]) == 0o644
    assert all(stat.S_ISREG(m) for m in modes.values())


def test_the_directory_and_files_are_owner_only(world, tmp_path):
    skill(world)
    dest = tmp_path / "out"

    archived = archive(world, dest)

    assert os.stat(dest).st_mode & 0o777 == 0o700
    assert os.stat(archived.path).st_mode & 0o777 == 0o600
    assert os.stat(dest / "index.jsonl").st_mode & 0o777 == 0o600


def test_a_rerun_writes_nothing_new_and_only_moves_last_seen(world, tmp_path):
    skill(world)
    dest = tmp_path / "out"
    first = archive(world, dest)
    before = os.stat(first.path)

    store = ArchiveStore(str(dest))
    archiver = Archiver(store, now="2026-10-13T00:00:00+00:00")
    again = archiver.archive(world.gate(), SKILL, expected=EXPECTED["basic"])
    archiver.record(again.value, name="basic", source=SKILL)
    archiver.close()

    assert again.value.written is False
    after = os.stat(first.path)
    assert (after.st_mtime_ns, after.st_ino) == (before.st_mtime_ns, before.st_ino)
    assert sorted(os.listdir(dest)) == sorted(["index.jsonl", f"{EXPECTED['basic']}.zip"])
    (row,) = index_of(dest)
    assert (row["first_seen"], row["last_seen"]) == ("2026-10-12T00:00:00+00:00", "2026-10-13T00:00:00+00:00")


def test_a_tree_that_changed_since_it_was_hashed_is_not_archived(world, tmp_path):
    skill(world)
    store = ArchiveStore(str(tmp_path / "out"))
    store.open()

    result = Archiver(store).archive(world.gate(), SKILL, expected="0" * 64)

    assert not result.ok and result.reason == "changed"
    assert os.listdir(tmp_path / "out") == []


def test_a_damaged_archive_in_the_store_is_refused_not_trusted(world, tmp_path):
    skill(world)
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / f"{EXPECTED['basic']}.zip").write_bytes(b"not a zip")

    result = Archiver(ArchiveStore(str(dest))).archive(world.gate(), SKILL, expected=EXPECTED["basic"])

    assert not result.ok and result.reason == "corrupt_archive"


# --------------------------------------------- reading someone else's zip


def _zip(*entries) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buffer.getvalue()


def test_a_zip_made_elsewhere_hashes_by_content_not_by_order_or_dates(world):
    entries = [(rel, body.encode(), stat.S_IFREG | mode) for rel, body, mode in BASIC]

    assert zip_content_sha256(_zip(*reversed(entries))) == EXPECTED["basic"]


def test_directories_and_links_in_a_zip_are_not_content(world):
    entries = [(rel, body.encode(), stat.S_IFREG | mode) for rel, body, mode in BASIC]
    extra = [("emptydir/", b"", stat.S_IFDIR | 0o755), ("link.md", b"SKILL.md", stat.S_IFLNK | 0o777)]

    assert zip_content_sha256(_zip(*entries, *extra)) == EXPECTED["basic"]


@pytest.mark.parametrize("name", ["../escape", "/abs", "a/../../escape", "C:evil", "back\\slash"])
def test_unsafe_entry_paths_are_refused(name):
    with pytest.raises(ArchiveError):
        zip_content_sha256(_zip((name, b"x", stat.S_IFREG | 0o644)))


def test_duplicate_entries_are_refused():
    with pytest.raises(ArchiveError, match="duplicate"):
        zip_content_sha256(_zip(("a", b"1", stat.S_IFREG | 0o644), ("./a", b"2", stat.S_IFREG | 0o644)))


def test_not_a_zip_is_refused():
    with pytest.raises(ArchiveError):
        zip_content_sha256(b"plain bytes")


# ------------------------------------------------------------- pipeline


def test_a_scan_archives_skills_and_links_them_from_the_snapshot(world, catalog, tmp_path):
    skill(world)
    dest = tmp_path / "archives"

    snapshot = discover(world.gate(), catalog, timestamp="2026-10-12T00:00:00+00:00",
                        archive_to=ArchiveStore(str(dest)))

    (asset,) = [a for a in snapshot.assets if a.kind is Kind.SKILL]
    assert asset.archive.path == str(dest / f"{EXPECTED['basic']}.zip")
    assert asset.archive.sha256 == hashlib.sha256(read(asset.archive.path)).hexdigest()
    (row,) = index_of(dest)
    assert row["source"] == "~/.claude/skills/basic"
    assert row["skill_sha256"] == asset.skill_sha256 == EXPECTED["basic"]
    assert row["archive_sha256"] == asset.archive.sha256
    assert from_dict(json.loads(to_json(snapshot))).assets == snapshot.assets
    assert any(p.name == "skill_archive" and p.status == "ran" for p in snapshot.coverage.probes)


def test_without_the_option_nothing_is_archived(world, catalog):
    skill(world)

    snapshot = discover(world.gate(), catalog)

    assert all(a.archive is None for a in snapshot.assets)


def test_the_cli_option_defaults_under_the_output_dir_and_dry_run_writes_nothing(world, tmp_path):
    skill(world)
    output = tmp_path / "output"

    cli.main(["--root", world.root, "--output-dir", str(output), "--dry-run", "--archive-skills"])
    assert not output.exists()

    cli.main(["--root", world.root, "--output-dir", str(output), "--archive-skills"])
    assert sorted(os.listdir(output / "skill-archives")) == sorted(["index.jsonl", f"{EXPECTED['basic']}.zip"])
