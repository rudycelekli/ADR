"""Interfaces detection needs from its host. Desktop fills each one, so detection never imports it."""

from typing import Protocol


class SessionSource(Protocol):
    """Captured agent sessions and agent activity, as Desktop's history keeps them.

    Reviews read sessions only through this port. Times are epoch seconds.
    """

    def session(self, session_id: str) -> dict | None:
        """One session with its project, digest, partial flag and payload, or None if it is gone."""

    def describe_sessions(self, session_ids: list[str]) -> dict[str, dict]:
        """The title, source and current digest of each listed session that still exists, by ID."""

    def recent_sessions(self, projects: list[str]) -> list[dict]:
        """Sessions in these projects, most recent activity first, with their id, project, digest,
        message_count, source and source_session_id."""

    def active_sessions(self, since: float) -> list[dict]:
        """The source and source_session_id of each session with activity after ``since``."""

    def hooks_active(self, since: float) -> bool:
        """Whether an agent hook ran after ``since``."""


class DeviceIdle(Protocol):
    """How long the owner has left the device alone."""

    def idle_seconds(self) -> float:
        """Seconds since the owner last used the device. Raises when that is unknown."""
