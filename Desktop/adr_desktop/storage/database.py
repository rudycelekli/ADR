"""The profile's SQLite database: connection, transactions and schema registration.

Each feature registers and queries its own tables; this module creates none.
"""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path


class Database:
    def __init__(self, state_dir: Path):
        self.path = state_dir / "desktop.sqlite3"
        if self.path.is_symlink():
            raise ValueError("The database must not be a symbolic link")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3):
            self.db.close()
            raise RuntimeError("This database was created by a newer ADR Desktop")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")

    def register(self, schema: str) -> None:
        """Create a feature's tables and indexes. The schema must only create what is missing."""
        with self.lock:
            self.db.executescript(schema)

    @contextmanager
    def transaction(self):
        with self.lock:
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def rows(self, query: str, values=()) -> list[dict]:
        with self.lock:
            return [dict(row) for row in self.db.execute(query, values).fetchall()]

    def one(self, query: str, values=()) -> dict | None:
        result = self.rows(query, values)
        return result[0] if result else None

    def execute(self, query: str, values=()) -> int:
        with self.transaction() as connection:
            return connection.execute(query, values).rowcount

    def close(self):
        with self.lock:
            self.db.close()
