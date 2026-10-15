import json

import pytest
from conftest import grant_token

from adr_desktop.detection.inline.credentials import detect_prompt_credentials
from adr_desktop.mcp_server import tools_for
from adr_desktop.storage.files import canonical, read_private_json
from adr_desktop.vault.contracts import NativeUnavailable
from adr_desktop.vault.environment import PROMPT_MESSAGE, validate_entry


def entry(runtime, name="My password", variable="MY_PASSWORD"):
    return runtime.environment_vault.create(name, variable)


def connection(runtime, tmp_path, identifiers, **options):
    return runtime.create_grant(
        "Synthetic execution",
        str(tmp_path),
        identifiers,
        kind="execution",
        confirm_execution=True,
        approval_mode="automatic",
        confirm_automatic=True,
        **options,
    )


@pytest.mark.parametrize(
    "variable",
    [
        "PATH",
        "HOME",
        "BASH_ENV",
        "PYTHONPATH",
        "NODE_OPTIONS",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "ADR_TOKEN",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_COUNT",
        "1INVALID",
        "bad-name",
    ],
)
def test_process_control_variables_cannot_be_secret_aliases(variable):
    with pytest.raises(ValueError):
        validate_entry("Synthetic", variable)


def test_generic_entry_has_no_origin_and_delegates_value_to_native(client, owner, runtime):
    response = client.post(
        "/api/environment-credentials",
        headers=owner,
        json={"name": "Database password", "env_name": "MY_DB_PASSWORD"},
    )
    assert response.status_code == 200
    assert response.json()["env_name"] == "MY_DB_PASSWORD"
    operation, payload = runtime.native.calls[-1]
    assert operation == "environment_prompt_store"
    assert set(payload) == {"id", "name", "env_name"}
    assert "synthetic-private-password" not in canonical(runtime.environment_vault.entries())
    assert read_private_json(runtime.state_dir / "vault-aliases.json") == {"names": ["MY_DB_PASSWORD"]}


def test_raw_values_are_rejected_without_validation_reflection(client, owner):
    secret = "synthetic-rejected-secret-123"
    response = client.post(
        "/api/environment-credentials",
        headers=owner,
        json={"name": "Synthetic", "env_name": "MY_PASSWORD", "value": secret},
    )
    assert response.status_code == 422
    assert secret not in response.text


def test_failed_native_save_never_grants_an_active_entry(vault, monkeypatch):
    def fail(*_args, **_kwargs):
        raise NativeUnavailable("synthetic_failure")

    monkeypatch.setattr(vault.native, "call", fail)
    with pytest.raises(NativeUnavailable):
        vault.environment.create("My password", "MY_PASSWORD")
    assert vault.environment.entries()[0]["state"] == "unconfirmed"
    assert read_private_json(vault.state_dir / "vault-aliases.json")["names"] == []


def test_no_plaintext_environment_fallback_without_native(vault):
    vault.native.connected = False
    with pytest.raises(NativeUnavailable):
        vault.environment.create("My password", "MY_PASSWORD")
    assert not vault.environment.entries()


def test_command_execution_requires_explicit_permission(runtime, tmp_path):
    saved = entry(runtime)
    with pytest.raises(ValueError, match="confirm"):
        runtime.create_grant(
            "Unconfirmed",
            str(tmp_path),
            [saved["id"]],
            kind="execution",
            approval_mode="automatic",
            confirm_automatic=True,
        )
    with pytest.raises(ValueError):
        runtime.create_grant("API-only", credentials=[saved["id"]], kind="vault")


def test_all_variable_access_requires_separate_explicit_consent(runtime, tmp_path):
    entry(runtime)
    with pytest.raises(ValueError, match="current and future"):
        connection(runtime, tmp_path, ["*"])


def test_opted_in_all_variable_connection_picks_up_new_values(vault, tmp_path):
    first = vault.environment.create("My password", "MY_PASSWORD")
    all_grant = vault.grants.issue(["*"], project=str(tmp_path))
    selected = vault.grants.issue([first["id"]], project=str(tmp_path))
    second = vault.environment.create("Second", "SECOND_PASSWORD")
    assert {row["id"] for row in vault.environment.permitted(all_grant)} == {first["id"], second["id"]}
    assert {row["id"] for row in vault.environment.permitted(selected)} == {first["id"]}
    result = vault.environment.execute(all_grant, 'printf "%s" "$SECOND_PASSWORD"')
    assert result["exit_code"] == 0
    arguments = next(
        payload for operation, payload in vault.native.calls if operation == "environment_execute"
    )
    assert set(arguments["ids"]) == {first["id"], second["id"]}


def test_connection_lists_names_and_runs_without_serializing_values(client, owner, runtime, tmp_path):
    saved = entry(runtime)
    grant = connection(runtime, tmp_path, [saved["id"]])
    headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
    listed = client.get("/api/agent/environment", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["variables"] == [
        {
            "id": saved["id"],
            "name": "My password",
            "env_name": "MY_PASSWORD",
        }
    ]
    response = client.post(
        "/api/agent/environment/run",
        headers=headers,
        json={"command": "python3 -c 'import os; print(bool(os.environ[\"MY_PASSWORD\"]))'"},
    )
    assert response.status_code == 200
    assert response.json()["stdout"] == "synthetic result"
    native_arguments = next(
        payload for operation, payload in runtime.native.calls if operation == "environment_execute"
    )
    assert native_arguments["ids"] == [saved["id"]]
    assert native_arguments["cwd"] == str(tmp_path)
    secret = runtime.native.environment_values[saved["id"]]
    assert secret not in canonical(native_arguments)
    assert secret not in response.text + listed.text
    assert secret not in canonical(runtime.store.rows("SELECT * FROM environment_runs"))
    assert secret not in canonical(runtime.store.rows("SELECT * FROM audit"))
    assert client.get("/api/agent/sessions", headers=headers).status_code == 403
    assert client.get("/api/agent/credentials", headers=headers).status_code == 403
    assert client.get("/api/environment-credentials", headers=headers).status_code == 401


def test_history_and_existing_api_connections_cannot_execute(client, runtime, tmp_path):
    history = runtime.create_grant("Context", kind="context", confirm_device_history=True)
    legacy = runtime.create_grant("Legacy", str(tmp_path))
    for grant in (history, legacy):
        headers = {"Authorization": "Bearer " + grant_token(runtime, grant)}
        assert client.get("/api/agent/environment", headers=headers).status_code == 403
        assert (
            client.post(
                "/api/agent/environment/run",
                headers=headers,
                json={"command": "pwd"},
            ).status_code
            == 403
        )
        assert "adr_run_command" not in {tool["name"] for tool in tools_for({"kind": grant["kind"]})}


def test_execution_connection_advertises_only_its_capabilities():
    assert {tool["name"] for tool in tools_for({"kind": "execution"})} == {
        "adr_status",
        "adr_list_environment",
        "adr_run_command",
    }


def test_execution_does_not_override_file_block_or_scope(vault, tmp_path):
    saved = vault.environment.create("My password", "MY_PASSWORD")
    grant = vault.grants.issue([saved["id"]], project=str(tmp_path))
    vault.guard.decision = "deny"
    with pytest.raises(PermissionError, match="protection"):
        vault.environment.execute(grant, "cat protected")
    vault.guard.decision = "pass"
    with pytest.raises(PermissionError, match="working directory"):
        vault.environment.execute(grant, "pwd", str(tmp_path.parent))
    assert not any(operation == "environment_execute" for operation, _ in vault.native.calls)


def test_file_ask_still_needs_native_approval_with_automatic_credential_grant(vault, tmp_path):
    saved = vault.environment.create("My password", "MY_PASSWORD")
    grant = vault.grants.issue([saved["id"]], project=str(tmp_path))
    vault.guard.decision, vault.guard.approves = "ask", False
    with pytest.raises(PermissionError, match="not approved"):
        vault.environment.execute(grant, "cat private")
    assert vault.guard.approvals == [
        {"agent": "Agent", "command": "cat private", "cwd": str(tmp_path), "variables": ["MY_PASSWORD"]}
    ]
    assert not any(operation == "environment_execute" for operation, _ in vault.native.calls)


def test_revoking_entry_blocks_use_and_removes_alias(vault, tmp_path):
    saved = vault.environment.create("My password", "MY_PASSWORD")
    grant = vault.grants.issue([saved["id"]], project=str(tmp_path))
    assert read_private_json(vault.state_dir / "vault-aliases.json") == {"names": ["MY_PASSWORD"]}
    vault.environment.remove(saved["id"])
    with pytest.raises(PermissionError):
        vault.environment.execute(grant, "printf done")
    assert read_private_json(vault.state_dir / "vault-aliases.json")["names"] == []


def test_prompt_check_blocks_known_values_without_storing_prompt(client, runtime):
    saved = entry(runtime)
    secret = runtime.native.environment_values[saved["id"]]
    text = "Please connect using " + secret
    response = client.post(
        "/api/hooks/prompt-check",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        json={"harness": "codex", "prompt": text},
    )
    assert response.status_code == 200
    assert response.json()["blocked"] is True
    assert response.json()["aliases"] == ["MY_PASSWORD"]
    assert response.json()["message"] == PROMPT_MESSAGE
    assert secret not in response.text
    assert text not in canonical(runtime.store.rows("SELECT * FROM prompt_blocks"))
    assert secret not in canonical(runtime.store.rows("SELECT * FROM audit"))
    assert (
        client.post(
            "/api/hooks/prompt-check",
            json={"harness": "codex", "prompt": "hello"},
        ).status_code
        == 401
    )


def test_prompt_with_variable_reference_can_be_resubmitted_after_saving(vault):
    vault.environment.create("My password", "MY_PASSWORD")
    result = vault.environment.check_prompt("Use $MY_PASSWORD with my program", "codex")
    assert result["blocked"] is False


def test_prompt_check_fails_closed_when_saved_values_cannot_be_checked(vault):
    vault.environment.create("My password", "MY_PASSWORD")
    vault.native.connected = False
    assert vault.environment.check_prompt("ordinary prompt", "codex")["blocked"] is True


def test_credential_membership_change_during_approval_cannot_reuse_old_secret(vault, tmp_path, monkeypatch):
    first = vault.environment.create("My password", "MY_PASSWORD")
    other = vault.environment.create("Other", "OTHER_PASSWORD")
    grant = vault.grants.issue([first["id"]], project=str(tmp_path), approval_mode="ask")

    def changed(*_arguments):
        vault.grants.items[grant["id"]] = {**grant, "credentials": json.dumps([other["id"]])}

    monkeypatch.setattr(vault.guard, "approve", changed)
    with pytest.raises(PermissionError, match="revoked"):
        vault.environment.execute(grant, "printf safe")
    assert not any(operation == "environment_execute" for operation, _ in vault.native.calls)


def test_known_tool_output_check_does_not_create_a_prompt_record(client, runtime):
    saved = entry(runtime)
    secret = runtime.native.environment_values[saved["id"]]
    response = client.post(
        "/api/hooks/output-check",
        headers={"Authorization": "Bearer " + runtime.hook_token},
        json={"harness": "codex", "text": secret},
    )
    assert response.status_code == 200 and response.json()["blocked"]
    assert secret not in response.text
    assert not runtime.store.rows("SELECT * FROM prompt_blocks")


@pytest.mark.parametrize(
    "text",
    [
        "My password is secret-example-789!",
        "password = 'synthetic-passphrase-123'",
        "password='x'",
        "password is password",
        "password = 123",
        "api_key: abc123456789",
        "DATABASE_PASSWORD=synthetic-unregistered-passphrase",
        '{"password": "synthetic-json-passphrase"}',
        "Use ghp_" + "a" * 36,
        "Use sk-proj-" + "b" * 40,
    ],
)
def test_unregistered_recognizable_credentials_stop_submission(text):
    assert detect_prompt_credentials(text)


@pytest.mark.parametrize(
    "text",
    [
        "Use $MY_PASSWORD",
        "password=$MY_PASSWORD",
        "password = os.environ['MY_PASSWORD']",
        "password is invalid",
        "Whatever password is in the vault should be available.",
        "password: <redacted>",
        "Please add password validation.",
    ],
)
def test_ordinary_instructions_and_references_are_not_passwords(text):
    assert detect_prompt_credentials(text) == []
