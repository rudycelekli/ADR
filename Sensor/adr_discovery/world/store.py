"""Where skill archives are written: the collector's only output besides
the snapshot itself.

Kept beside the gate because it touches the host, and kept apart from it
because the gate only ever reads. Everything here is local and owner-only:
the directory is 0700 and every file 0600, since an archive holds a copy of
whatever the skill held.
"""

from __future__ import annotations

import os
import tempfile


class ArchiveStore:
    """A content-addressed directory: a name, once written, is never rewritten."""

    INDEX = "index.jsonl"

    def __init__(self, directory: str) -> None:
        self.directory = os.path.abspath(directory)

    def open(self) -> None:
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        if os.path.islink(self.directory):
            raise OSError(f"archive directory must not be a symlink: {self.directory}")
        os.chmod(self.directory, 0o700)

    def path_of(self, name: str) -> str:
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise ValueError(f"not a plain file name: {name!r}")
        return os.path.join(self.directory, name)

    def has(self, name: str) -> bool:
        return os.path.isfile(self.path_of(name))

    def read(self, name: str) -> bytes | None:
        try:
            with open(self.path_of(name), "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def put_once(self, name: str, data: bytes) -> bool:
        """Write `name` unless it exists. True when this call wrote it.

        Written to a temporary file and linked into place, so a reader never
        sees a partial archive and a concurrent writer of the same name
        cannot replace it.
        """
        target = self.path_of(name)
        if os.path.exists(target):
            return False
        temporary = self._write_temporary(data)
        try:
            os.link(temporary, target)
        except FileExistsError:
            return False
        finally:
            os.unlink(temporary)
        return True

    def replace(self, name: str, data: bytes) -> None:
        """Atomically replace a mutable file (the index)."""
        os.replace(self._write_temporary(data), self.path_of(name))

    def _write_temporary(self, data: bytes) -> str:
        # mkstemp creates the file 0600, and a link or rename keeps the mode.
        fd, temporary = tempfile.mkstemp(dir=self.directory, prefix=".partial-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            os.unlink(temporary)
            raise
        return temporary
