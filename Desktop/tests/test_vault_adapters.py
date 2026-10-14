"""Desktop fills the vault's ports, and the vault hears when Desktop revokes a grant."""

import json

import pytest
from conftest import add_credential

from adr_desktop.evaluate import VaultGuard
from adr_desktop.runtime import StoredGrants


def test_desktop_guard_decides_vault_commands_under_the_current_policy(runtime, tmp_path):
    guard = VaultGuard(runtime)
    assert guard.evaluate("cat protected", str(tmp_path), {"HOME": str(tmp_path)}).decision == "pass"
    runtime.change_policy(add={"path": str(tmp_path / "protected"), "action": "block", "kind": "file"})
    assert guard.evaluate("cat protected", str(tmp_path), {"HOME": str(tmp_path)}).decision == "deny"


def test_desktop_guard_asks_the_owner_in_the_menu_bar_app(runtime, tmp_path):
    with pytest.raises(PermissionError, match="not approved"):
        VaultGuard(runtime).approve("Agent", "printf safe", str(tmp_path), ["MY_PASSWORD"])
    operation, arguments = runtime.native.calls[-1]
    assert (operation, arguments["harness"], arguments["tool"]) == (
        "approve_tool", "Agent", "Credential-backed command",
    )
    assert json.loads(arguments["operation"]) == {
        "command": "printf safe", "cwd": str(tmp_path), "variables": ["MY_PASSWORD"],
    }
    # The approval gave back its turn in the queue the hooks share.
    assert runtime.hook_approvals.pending == 0


def test_desktop_grants_give_the_vault_only_unrevoked_grants(runtime):
    grant = runtime.create_grant("Agent", kind="agent", confirm_agent=True)
    grants = StoredGrants(runtime.store)
    assert grants.active(grant["id"])["name"] == "Agent"
    runtime.revoke_grant(grant["id"])
    assert grants.active(grant["id"]) is None


def test_revoking_a_connection_revokes_its_credential_requests(runtime):
    credential = add_credential(runtime)
    grant = runtime.create_grant("Agent", "/workspace", [credential["id"]])
    stored = runtime.store.one("SELECT * FROM grants WHERE id=?", (grant["id"],))
    pending = runtime.broker.enqueue(stored, credential["id"], "/user")
    runtime.revoke_grant(grant["id"])
    assert runtime.broker.result(stored, pending["request_id"]) == {
        "request_id": pending["request_id"], "state": "revoked", "result": None, "error": None,
    }
    with pytest.raises(ValueError):
        runtime.broker.approve(pending["request_id"], True)
