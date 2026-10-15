"""Values that cross the boundary between Desktop and protection."""

from dataclasses import asdict, dataclass, field

DENIAL_REASONS = {
    "protected_path": "ADR blocked access to a protected file or configuration.",
    "approval_denied": "This operation was denied in ADR's approval dialog.",
    "approval_expired": "ADR's approval request expired. Retry the operation if it is still needed.",
    "approval_queue_full": "ADR's approval queue is full. Finish pending approvals, then retry.",
    "app_unavailable": "ADR's approval dialog is unavailable. Open the ADR menu-bar app and retry.",
    "invalid_request": "ADR could not validate this tool request; no approval was granted.",
    "policy_unavailable": "ADR could not load its local protection policy. Open ADR to check its status.",
    "safety_timeout": "ADR's safety check timed out; no approval was granted.",
    "vault_execution_required": (
        "Use adr_run_command for saved $VARIABLE credentials. "
        "It is built into the ADR plugin; no separate vault setup is needed. "
        "Local programs receive the values and the model receives filtered output."
    ),
    "credential_check_unavailable": (
        "ADR could not check this tool result against saved credentials. "
        "The result was withheld. Open Credential vault in ADR to check storage."
    ),
    "known_malicious_artifact": (
        "ADR blocked a known malicious artifact. Review Malicious artifacts in ADR."
    ),
}


@dataclass
class Decision:
    decision: str = "pass"
    reason: str = "No protected path matched"
    paths: list[str] = field(default_factory=list)
    rule_id: str | None = None
    tool: str = ""
    session_id: str = ""
    credential_kinds: list[str] = field(default_factory=list)
    phase: str = "pre"
    reason_code: str = "no_match"
    approval_requested: bool = False
    artifact: dict | None = None

    def as_dict(self):
        result = asdict(self)
        # Closed reason codes are for the native bridge. The optional approval
        # marker distinguishes owner-approved operations from routine passes.
        result.pop("reason_code")
        result["approval_requested"] = self.approval_requested or self.decision == "ask"
        if not result["approval_requested"]:
            result.pop("approval_requested")
        if result["artifact"] is None:
            result.pop("artifact")
        return result
