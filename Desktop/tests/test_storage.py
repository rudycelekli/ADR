"""Storage: the profile database's connection, transactions, schema registration, IDs and private files."""

import sqlite3
from pathlib import Path

import pytest

from adr_desktop.storage.database import Database
from adr_desktop.storage.files import atomic_json, prepare_state_dir, read_private_json
from adr_desktop.storage.ids import new_id
from adr_desktop.store import Store

# Written with iterdump from a profile the code at ec543ed created: a Runtime with two sessions
# (one a subagent), a credential, a history grant and an audit entry. The search table's rows are
# left out of the dump; its shadow tables already hold the index.
FORMAT_3_PROFILE = Path(__file__).parent / "fixtures" / "profile_format_3.sql"
NOTES = "CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY, body TEXT NOT NULL);"


def database_contents(path):
    database = sqlite3.connect(path)
    try:
        version = database.execute("PRAGMA user_version").fetchone()[0]
        schema = database.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        tables = [name for kind, name, _, sql in schema if kind == "table" and "VIRTUAL" not in sql]
        rows = {
            name: sorted(database.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr)
            for name in tables
        }
        return version, schema, rows
    finally:
        database.close()


def format_3_profile(directory):
    database = sqlite3.connect(directory / "desktop.sqlite3")
    database.executescript(FORMAT_3_PROFILE.read_text())
    database.close()
    return directory


def test_storage_has_no_tables_of_its_own_and_a_feature_registers_its_schema(tmp_path):
    database = Database(prepare_state_dir(tmp_path / "profile"))
    try:
        assert database.rows("SELECT name FROM sqlite_master") == []
        database.register(NOTES)
        database.execute("INSERT INTO notes VALUES (?,?)", ("one", "kept"))
        # A feature registers its schema on every start; existing rows stay.
        database.register(NOTES)
        assert database.one("SELECT body FROM notes WHERE id=?", ("one",)) == {"body": "kept"}
    finally:
        database.close()


def test_a_failed_transaction_writes_nothing(tmp_path):
    database = Database(prepare_state_dir(tmp_path / "profile"))
    try:
        database.register(NOTES)
        with pytest.raises(ValueError, match="synthetic"):
            with database.transaction() as connection:
                connection.execute("INSERT INTO notes VALUES (?,?)", ("one", "partial"))
                raise ValueError("synthetic failure")
        assert database.rows("SELECT * FROM notes") == []
    finally:
        database.close()


def test_storage_refuses_a_database_from_a_newer_format(tmp_path):
    directory = prepare_state_dir(tmp_path / "profile")
    newer = sqlite3.connect(directory / "desktop.sqlite3")
    newer.execute("PRAGMA user_version=4")
    newer.close()
    with pytest.raises(RuntimeError, match="newer ADR Desktop"):
        Database(directory)


def test_new_ids_are_distinct_128_bit_hex_strings():
    identifiers = {new_id() for _ in range(100)}
    assert len(identifiers) == 100
    assert all(len(value) == 32 and set(value) <= set("0123456789abcdef") for value in identifiers)


def test_profile_files_are_private_to_their_owner(tmp_path):
    directory = prepare_state_dir(tmp_path / "profile")
    atomic_json(directory / "notes.json", {"kept": True})
    assert read_private_json(directory / "notes.json") == {"kept": True}
    shared = directory / "shared.json"
    shared.write_text("{}")
    shared.chmod(0o644)
    with pytest.raises(ValueError, match="private to its owner"):
        read_private_json(shared)


def test_a_new_profile_gets_the_format_3_schema(runtime, tmp_path):
    version, schema, _ = database_contents(runtime.store.path)
    expected = database_contents(format_3_profile(prepare_state_dir(tmp_path / "old")) / "desktop.sqlite3")
    assert (version, schema) == (3, expected[1])


def test_a_format_3_profile_opens_without_migration(tmp_path):
    directory = format_3_profile(prepare_state_dir(tmp_path / "profile"))
    before = database_contents(directory / "desktop.sqlite3")
    store = Store(directory)
    try:
        assert store.sessions(grouped=True)["total"] == 1
        assert store.search_history("parser")["items"][0]["kind"] == "subagent"
    finally:
        store.close()
    assert database_contents(directory / "desktop.sqlite3") == before
