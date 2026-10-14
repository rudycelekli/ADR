"""Compose exact artifact matches with existing file and harness permissions."""

import time
from pathlib import Path

from .detection.inline.artifacts import READ_TOOLS, identify_operation
from .detection.inline.feed.api_v1 import compile_generation
from .detection.operation import PATH_KEYS
from .integrations import agents
from .integrations.events import event_fields, event_operation
from .mcp_trust import trusted_tool
from .protection.contracts import DENIAL_REASONS, Decision
from .protection.policy import evaluate
from .storage.files import canonical


def evaluate_operation(event, harness, snapshot, *, state_dir, allow_adr_trust=True,
                       environment=None, artifact_scope="all") -> Decision:
    if artifact_scope not in ("all", "direct_files"):
        raise ValueError("Unsupported artifact evaluation scope")
    if allow_adr_trust and trusted_tool(event, harness, state_dir):
        tool, _, _, session = event_fields(event, harness)
        base = Decision("pass", "ADR MCP permission checked", tool=tool, session_id=session)
    else:
        base = evaluate(event_operation(event, harness), snapshot)
    if base.decision == "deny":
        return base
    threats = snapshot.get("threats")
    if threats is None:
        return base
    if not isinstance(threats, dict) or not isinstance(threats.get("enabled"), bool):
        raise ValueError("Invalid threat policy")
    generation = compile_generation(threats.get("generation"))
    if not threats["enabled"]:
        return base
    if artifact_scope == "direct_files":
        # An approval daemon does not inherit the invoking harness's registry,
        # CODEX_HOME, or XDG context. Only literal absolute file reads have an
        # artifact identity independent of that missing process context.
        tool, arguments, _, _ = event_fields(event, harness)
        paths = [arguments[key] for key in PATH_KEYS if arguments.get(key) is not None]
        if tool.lower() not in READ_TOOLS or not paths or any(
            not isinstance(path, str) or not Path(path).is_absolute()
            or path.startswith(("~", "file:")) for path in paths
        ):
            return base
    evidence = identify_operation(event_operation(event, harness), agents, environment=environment)
    for candidate in evidence.candidates:
        matches = generation.match(candidate.subject)
        if matches:
            match = matches[0]
            base.decision = "deny"
            base.reason_code = "known_malicious_artifact"
            base.reason = DENIAL_REASONS[base.reason_code]
            base.artifact = {
                "indicator_id": match["indicator_id"],
                "source_id": match["source_id"],
                "kind": match["kind"],
                "generation": match["generation_digest"],
                "target_display": match["target_display"],
            }
            return base
    return base


class VaultGuard:
    """Fills the vault's Guard port. A credential-backed command is decided as an agent's Bash call under
    the current policy, and the owner approves it in the menu-bar app, in turn with the hooks' approvals."""

    def __init__(self, runtime):
        self.runtime = runtime

    def evaluate(self, command, cwd, environment):
        event = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd}
        decision = evaluate_operation(
            event, "codex", self.runtime.policy, state_dir=self.runtime.state_dir, allow_adr_trust=False,
            environment=environment,
        )
        if decision.decision == "deny" and decision.artifact:
            self.runtime.threats.record_block(decision, harness="vault", source="vault")
        return decision

    def approve(self, agent, command, cwd, variables):
        deadline = time.monotonic() + 80
        ticket, failure = self.runtime.hook_approvals.acquire(deadline)
        if ticket is None:
            raise PermissionError("ADR could not obtain approval for this command")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PermissionError("Command approval expired")
            answer = self.runtime.native.call(
                "approve_tool",
                {
                    "harness": agent,
                    "tool": "Credential-backed command",
                    "operation": canonical(
                        {
                            "command": command,
                            "cwd": cwd,
                            "variables": variables,
                        }
                    ),
                    "expires_at": time.time() + remaining,
                },
                timeout=remaining,
            )
            if answer.get("allowed") is not True or time.monotonic() >= deadline:
                raise PermissionError("Credential-backed command was not approved")
        finally:
            self.runtime.hook_approvals.release(ticket)
