"""Values that cross the boundary between Desktop and detection."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Operation:
    """A tool call an agent asks to make, as Desktop decoded it from the agent's event."""

    tool: str
    arguments: dict
    cwd: str
