"""Values that cross the boundary between Desktop and detection."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Operation:
    """A tool call an agent asks to make, as Desktop decoded it from the agent's event."""

    harness: str
    tool: str
    arguments: dict
    cwd: str
    # The MCP server the agent says the tool belongs to, as the event gave it, or None.
    mcp_server: dict | None = None
