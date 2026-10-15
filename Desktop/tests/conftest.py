import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from adr_desktop.api import create_app
from adr_desktop.protection.contracts import Decision
from adr_desktop.runtime import Runtime
from adr_desktop.storage.files import prepare_state_dir
from adr_desktop.store import Store
from adr_desktop.vault.broker import Broker
from adr_desktop.vault.environment import EnvironmentVault


class FakeNative:
    connected = True

    def __init__(self):
        self.calls = []
        self.profiles = {}
        self.environment_values = {}
        self.local_ids = set()

    def call(self, operation, arguments=None, timeout=30):
        arguments = arguments or {}
        self.calls.append((operation, arguments))
        if operation == "vault_prompt_store":
            assert "secret" not in arguments
            self.profiles[arguments["id"]] = dict(arguments)
            self.local_ids.add(arguments["id"])
            return {"stored": True}
        if operation == "environment_prompt_store":
            assert "secret" not in arguments and "value" not in arguments
            self.profiles[arguments["id"]] = dict(arguments)
            self.environment_values[arguments["id"]] = "synthetic-private-password-789!"
            self.local_ids.add(arguments["id"])
            return {"stored": True}
        if operation == "vault_storage_status":
            return {"backend": "local_encrypted", "entries": [
                {"id": identifier, "storage": "local_encrypted",
                 "state": "available" if identifier in self.local_ids else "missing",
                 "kind": "environment" if identifier in self.environment_values else "service"}
                for identifier in arguments["ids"]
            ]}
        if operation == "vault_migrate_legacy":
            results = []
            for identifier in arguments["ids"]:
                if identifier not in self.profiles:
                    results.append({"id": identifier, "status": "failed",
                                    "reason_code": "legacy_keychain_missing"})
                else:
                    results.append({"id": identifier, "status":
                                    "already_local" if identifier in self.local_ids else "migrated"})
                    self.local_ids.add(identifier)
            return {"backend": "local_encrypted", "results": results, "keychain_originals_retained": True}
        if operation == "vault_check_text":
            matches = [
                identifier for identifier in arguments["environment_ids"]
                if self.environment_values.get(identifier) in arguments["text"]
            ]
            return {
                "checked": True, "matched": bool(matches),
                "aliases": [self.profiles[identifier]["env_name"] for identifier in matches],
            }
        if operation == "environment_execute":
            return {"exit_code": 0, "stdout": "synthetic result", "stderr": "", "redacted": False}
        if operation == "vault_delete":
            self.profiles.pop(arguments["id"], None)
            self.environment_values.pop(arguments["id"], None)
            self.local_ids.discard(arguments["id"])
            return {"removed": True}
        if operation == "vault_perform":
            return {"status": 200, "content_type": "application/json", "body": {"login": "synthetic"}}
        if operation in ("login_status", "set_login"):
            return {"available": True, "enabled": False, "requires_approval": False}
        if operation == "approve_tool":
            return {"allowed": False}
        if operation == "approve_integration":
            return {"allowed": False}
        if operation == "approve_vault_migration":
            return {"allowed": False}
        if operation == "file_access_identity":
            return {"app_name": "ADR", "bundle_path": "/Applications/ADR.app",
                    "full_disk_access": "not_determined"}
        if operation == "open_access_settings":
            return {"request_accepted": True, "grants_access": False, "full_disk_access": "not_determined"}
        raise ValueError("Unsupported synthetic operation")


class FakeGuard:
    """Fake vault Guard: decides every command the same way, and the owner approves or declines."""

    def __init__(self):
        self.decision, self.artifact, self.approves = "pass", None, True
        self.approvals = []

    def evaluate(self, command, cwd, environment):
        return Decision(decision=self.decision, artifact=self.artifact)

    def approve(self, agent, command, cwd, variables):
        self.approvals.append({"agent": agent, "command": command, "cwd": cwd, "variables": variables})
        if not self.approves:
            raise PermissionError("Credential-backed command was not approved")


class FakeGrants:
    """Fake vault Grants: the grants Desktop issued and has not revoked."""

    def __init__(self):
        self.items = {}

    def issue(self, credentials, *, kind="execution", project="", approval_mode="automatic", name="Agent"):
        grant = {
            "id": uuid.uuid4().hex, "name": name, "kind": kind, "project": project,
            "credentials": json.dumps(credentials), "approval_mode": approval_mode,
        }
        self.items[grant["id"]] = grant
        return grant

    def active(self, grant_id):
        return self.items.get(grant_id)


@pytest.fixture
def vault(tmp_path):
    """Vault's entry points over fake ports, without Desktop's runtime."""
    state = prepare_state_dir(tmp_path / "vault-state")
    store = Store(state)
    native, guard, grants = FakeNative(), FakeGuard(), FakeGrants()
    broker = Broker(store, native, grants)
    environment = EnvironmentVault(store, state, native, broker, guard, grants)
    yield SimpleNamespace(
        store=store, state_dir=state, native=native, guard=guard, grants=grants,
        broker=broker, environment=environment,
    )
    store.close()


class FakePluginDriver:
    def __init__(self):
        self.calls = []

    def executable(self, harness):
        return "/synthetic/" + harness

    def install(self, harness, catalog, market, executable, *, market_registered=False):
        self.calls.append(("install", harness, str(catalog), market))

    def remove(self, harness, market, executable):
        self.calls.append(("remove", harness, market))


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    # Exercise the real resolver without inheriting the runner/developer's
    # configuration roots. Patching only imported function names leaves other
    # callers pointing at a different (potentially real) agent profile.
    for name in ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)
    state = prepare_state_dir(tmp_path / "state")
    result = Runtime(state, FakeNative(), start_collectors=False)
    result.port = 48321
    yield result
    result.close()


@pytest.fixture
def client(runtime):
    with TestClient(create_app(runtime), base_url="http://127.0.0.1:48321") as result:
        yield result


@pytest.fixture
def owner(runtime):
    return {"Authorization": f"Bearer {runtime.owner_token}"}


def sample_session(*, source="claude", session_id="one", project="/workspace/sample", content=None):
    return {
        "source": source,
        "session_id": session_id,
        "username": "synthetic",
        "timestamp": "2026-09-30T10:00:00Z",
        "project_path": project,
        "model": "example-model",
        "uuid": "upstream-stable-id",
        "chat_history": [
            {"role": "user", "content": content or "Add input validation", "tools": []},
            {
                "role": "assistant",
                "content": "I checked the handler.",
                "tools": [
                    {"tool_name": "Read", "arguments": {"file_path": "app.py"}, "result": "original output"},
                ],
            },
        ],
    }


def add_credential(runtime):
    return runtime.broker.create(
        {
            "name": "Synthetic GitHub",
            "origin": "https://api.github.com",
            "auth_type": "bearer",
            "allowed_paths": ["/user", "/repos"],
        }
    )


def grant_token(runtime, grant):
    return json.loads((runtime.state_dir / "agents" / f"{grant['id']}.json").read_text())["token"]
