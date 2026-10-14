"""Interfaces the vault needs from its host. Desktop fills each one, so the vault never imports it."""

from typing import Protocol


class NativeVault(Protocol):
    """The menu-bar app's half of the vault: secret entry and storage, the command runner and the HTTPS
    transport. Secret values never cross this port."""

    connected: bool

    def call(self, operation: str, arguments: dict | None = None, timeout: float = 30) -> dict:
        """Run one native operation and return its result.

        Raises NativeUnavailable, whose message is a closed, content-free code, and NativeTimedOut when
        the operation does not finish within ``timeout`` seconds."""


class Guard(Protocol):
    """ADR's protection decision on a credential-backed command, and the owner's approval of it."""

    def evaluate(self, command: str, cwd: str, environment: dict[str, str]):
        """Decide ``command`` as an agent's shell command run in ``cwd`` with ``environment``.

        The result's ``decision`` is "pass", "ask" or "deny"; its ``artifact`` is set when a known
        malicious artifact caused the denial."""

    def approve(self, agent: str, command: str, cwd: str, variables: list[str]) -> None:
        """Ask the owner to let ``agent`` run ``command`` in ``cwd`` with the saved ``variables``.

        Returns once the owner approved. Raises PermissionError when the owner declined or no answer
        came in time."""


class Grants(Protocol):
    """The agent connections Desktop issues. The vault works within the credentials a grant gives it."""

    def active(self, grant_id: str) -> dict | None:
        """The grant as Desktop stores it, or None once it is revoked or gone.

        A grant has its id, name, kind, project, approval_mode, and credentials: a JSON list of
        credential IDs, or ["*"] for every saved variable."""
