"""Credential metadata and authorized execution. Secret values stay in the native host."""

import json
import re
import threading
from pathlib import Path

from ..detection.inline.credentials import detect_credentials, detect_prompt_credentials, find_credentials
from ..detection.operation import resolve_path
from ..storage.clock import utcnow
from ..storage.files import atomic_json, canonical
from ..storage.ids import new_id
from .contracts import SAFE_ERRORS, NativeTimedOut, NativeUnavailable
from .ports import Grants, Guard, NativeVault

ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
RESERVED = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "PWD",
        "OLDPWD",
        "TMPDIR",
        "TMP",
        "TEMP",
        "ENV",
        "BASH_ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "IFS",
        "CDPATH",
        "GLOBIGNORE",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "NODE_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "PERL5LIB",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "PS4",
        "CODEX_HOME",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
    }
)
PROMPT_LIMIT = 256 * 1024
PROMPT_MESSAGE = (
    "ADR stopped this prompt because it may contain a credential. "
    "If it is not already saved, open ADR → Credential vault → Add credential and save it there. "
    "Replace the value with its $ENVIRONMENT_NAME and submit again. "
    "Use adr_run_command for commands or code that need the saved environment variable."
)
UNAVAILABLE_MESSAGE = (
    "ADR could not finish checking this prompt. Open the ADR menu-bar app, "
    "then submit again. The prompt was not approved for model submission."
)


def validate_entry(name, env_name):
    name, env_name = name.strip(), env_name.strip()
    if not name or len(name) > 80 or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Choose a short name for the credential")
    upper = env_name.upper()
    if (
        not ENV_NAME.fullmatch(env_name)
        or upper in RESERVED
        or upper.startswith(("LD_", "DYLD_", "BASH_FUNC_", "GIT_CONFIG_", "ADR_"))
    ):
        raise ValueError("Choose a credential variable such as MY_PASSWORD, not a process-control variable")
    return name, env_name


class NativeSavedValues:
    """Fills detection's SavedValueCheck: the native vault compares text with the listed saved values."""

    def __init__(self, native, environment_ids, service_ids):
        self.native = native
        self.environment_ids, self.service_ids = environment_ids, service_ids

    def check(self, text, purpose):
        if not self.environment_ids and not self.service_ids:
            return False, []
        if not self.native.connected:
            raise NativeUnavailable()
        checked = self.native.call(
            "vault_check_text",
            {
                "text": text, "environment_ids": self.environment_ids, "service_ids": self.service_ids,
                "purpose": purpose,
            },
            timeout=2,
        )
        if checked.get("checked") is not True:
            raise NativeUnavailable()
        aliases = [
            name
            for name in checked.get("aliases", [])
            if isinstance(name, str) and ENV_NAME.fullmatch(name)
        ]
        return bool(checked.get("matched")), aliases


class EnvironmentVault:
    """Saved variables, their aliases file and credential-backed runs. ``broker`` lists the API-only
    credentials, whose values are also kept out of prompts and results."""

    def __init__(self, store, state_dir: Path, native: NativeVault, broker, guard: Guard, grants: Grants):
        self.store, self.state_dir, self.native = store, state_dir, native
        self.broker, self.guard, self.grants = broker, guard, grants
        self.slots = threading.BoundedSemaphore(2)
        self.store.execute(
            "UPDATE environment_runs SET state='interrupted' WHERE state IN ('checking','running')"
        )
        self.publish_aliases()

    def entries(self):
        return self.store.rows(
            "SELECT id,name,env_name,state,created_at FROM environment_credentials ORDER BY created_at DESC"
        )

    def publish_aliases(self):
        atomic_json(
            self.state_dir / "vault-aliases.json",
            {
                "names": [row["env_name"] for row in self.entries() if row["state"] == "active"],
            },
        )

    def create(self, name, env_name):
        name, env_name = validate_entry(name, env_name)
        if not self.native.connected:
            raise NativeUnavailable("Open ADR's menu-bar app to save a credential")
        if len(self.entries()) >= 64:
            raise ValueError("This preview supports up to 64 environment credentials")
        identifier = new_id()
        self.store.execute(
            "INSERT INTO environment_credentials VALUES (?,?,?,?,?)",
            (identifier, name, env_name, "preparing", utcnow()),
        )
        try:
            receipt = self.native.call(
                "environment_prompt_store",
                {"id": identifier, "name": name, "env_name": env_name},
                timeout=120,
            )
            if receipt.get("stored") is not True:
                raise NativeUnavailable("save_unconfirmed")
        except Exception as error:
            if isinstance(error, NativeUnavailable) and str(error) == "cancelled":
                self.store.execute("DELETE FROM environment_credentials WHERE id=?", (identifier,))
                raise ValueError("Canceled; no credential was saved") from None
            self.store.execute(
                "UPDATE environment_credentials SET state='unconfirmed' WHERE id=?", (identifier,),
            )
            code = (
                str(error) if isinstance(error, NativeUnavailable) and str(error) in SAFE_ERRORS
                else "save_unconfirmed"
            )
            self.store.audit("credential_save_unconfirmed", "Credential save needs verification",
                             {"id": identifier, "reason_code": code})
            raise NativeUnavailable(
                "The save was not confirmed. Refresh Credential vault and recover this saved entry if "
                "a valid local copy is found. Do not delete it or save a replacement yet."
            ) from None
        self.store.execute(
            "UPDATE environment_credentials SET state='active' WHERE id=? AND state != 'revoked'",
            (identifier,),
        )
        current = self.store.one("SELECT * FROM environment_credentials WHERE id=?", (identifier,))
        if not current or current["state"] != "active":
            raise NativeUnavailable("credential_removed_during_save")
        self.publish_aliases()
        self.store.audit("environment_added", "Saved an environment credential", {"id": identifier})
        return current

    def remove(self, identifier):
        if not self.store.one("SELECT id FROM environment_credentials WHERE id=?", (identifier,)):
            raise ValueError("Credential not found")
        self.store.execute("UPDATE environment_credentials SET state='revoked' WHERE id=?", (identifier,))
        self.publish_aliases()
        self.native.call("vault_delete", {"id": identifier})
        self.store.execute("DELETE FROM environment_credentials WHERE id=?", (identifier,))
        self.store.audit("environment_removed", "Removed an environment credential", {"id": identifier})

    def permitted(self, grant):
        if grant["kind"] not in ("execution", "agent"):
            raise PermissionError("This connection does not grant credential-backed command execution")
        permitted = set(json.loads(grant["credentials"]))
        return [
            row
            for row in self.entries()
            if ("*" in permitted or row["id"] in permitted) and row["state"] == "active"
        ]

    def check_prompt(self, prompt, harness, *, record=True):
        if not isinstance(prompt, str) or len(prompt.encode()) > PROMPT_LIMIT:
            return {"blocked": True, "message": UNAVAILABLE_MESSAGE}
        ids = [row["id"] for row in self.entries() if row["state"] == "active"]
        # Include existing API credentials without granting execution access to them.
        service_ids = [row["id"] for row in self.broker.credentials() if row["state"] == "active"]
        try:
            kinds, aliases = find_credentials(
                prompt, NativeSavedValues(self.native, ids, service_ids), prompt=record,
            )
        except Exception as error:
            # Closed, content-free diagnostics. Availability is not evidence
            # of a pasted secret, and the agent must not be told otherwise.
            code = "credential_check_unavailable"
            if isinstance(error, NativeTimedOut):
                code = "credential_check_timeout"
            elif isinstance(error, NativeUnavailable) and str(error) in SAFE_ERRORS:
                code = str(error)
            return {
                "blocked": True, "unavailable": True, "reason_code": code,
                "message": UNAVAILABLE_MESSAGE,
            }
        if not kinds:
            return {"blocked": False, "message": ""}
        if record:
            self.store.execute(
                "INSERT INTO prompt_blocks(created_at,harness,kinds,aliases) VALUES (?,?,?,?)",
                (utcnow(), harness, canonical(sorted(set(kinds))), canonical(aliases)),
            )
            # No prompt, matched value, snippet, or value-derived hash is retained.
            self.store.audit("prompt_blocked", "Stopped a prompt containing a possible credential")
        return {"blocked": True, "message": PROMPT_MESSAGE, "aliases": aliases}

    def model_history(self, value):
        """Check the model-bound copy only; never alter captured source records."""
        checked = self.check_prompt(canonical(value), "history", record=False)
        if checked["blocked"]:
            return {
                "output_withheld": True,
                "message": (
                    "ADR withheld this history result because it may contain a credential or could not "
                    "be checked. Open ADR to view the original locally, or try a smaller page. "
                    "Use saved variable names with adr_run_command when you need credentials."
                ),
            }
        return value

    def execute(self, grant, command, cwd="", timeout_seconds=30):
        entries = self.permitted(grant)
        if not entries or (
            json.loads(grant["credentials"]) != ["*"]
            and len(entries) != len(json.loads(grant["credentials"]))
        ):
            raise PermissionError("No usable saved credentials; open ADR's Credential vault")
        if not isinstance(command, str) or not command.strip() or len(command.encode()) > 16384:
            raise ValueError("Use a nonempty command of at most 16 KiB")
        if "\x00" in command or detect_prompt_credentials(command):
            raise ValueError("Use $VARIABLE references in commands, not pasted credential values")
        if not self.native.connected:
            raise NativeUnavailable("Open the ADR menu-bar app before running a credential-backed command")
        if grant["kind"] == "agent":
            if not cwd or not Path(cwd).is_absolute():
                raise ValueError("Supply the command's absolute working directory in cwd")
            directory = resolve_path(cwd, str(Path.home()))
            if not directory.is_dir():
                raise ValueError("Choose an existing working directory")
        else:
            root = resolve_path(grant["project"], str(Path.home()))
            directory = resolve_path(cwd or str(root), str(root))
        if grant["kind"] != "agent" and (not directory.is_dir() or not directory.is_relative_to(root)):
            raise PermissionError("The working directory must be inside this connection's project")
        if not self.slots.acquire(blocking=False):
            raise ValueError("ADR is already running two credential-backed commands; try again shortly")
        identifier = new_id()
        # The native runner does not inherit the daemon's environment. Saved
        # aliases are opaque here: a registry-control alias cannot be guessed
        # to contain a public URL, and no value crosses the native boundary.
        execution_environment = {
            "HOME": str(Path.home()),
            **{row["env_name"]: "__ADR_SAVED_VALUE__" for row in entries},
        }
        self.store.execute(
            "INSERT INTO environment_runs VALUES (?,?,?,?,NULL)",
            (identifier, grant["id"], "checking", utcnow()),
        )
        try:
            checked = self.check_prompt(command, "vault")
            if checked["blocked"]:
                if checked.get("unavailable"):
                    raise NativeUnavailable(checked["reason_code"])
                raise PermissionError("Use saved variable names instead of literal credentials in commands")
            decision = self.guard.evaluate(command, str(directory), execution_environment)
            if decision.decision == "deny":
                if decision.artifact:
                    raise PermissionError("known_malicious_artifact")
                raise PermissionError("ADR file protection blocked this command")
            approved = False
            if grant["approval_mode"] == "ask" or decision.decision == "ask":
                self.guard.approve(
                    grant["name"], command, str(directory), [row["env_name"] for row in entries],
                )
                approved = True
            current = self.grants.active(grant["id"])
            if not current or not {row["id"] for row in entries} <= {
                row["id"] for row in self.permitted(current)
            }:
                raise PermissionError("Access was revoked")
            rechecked = self.guard.evaluate(command, str(directory), execution_environment)
            if rechecked.decision == "deny" or (rechecked.decision == "ask" and not approved):
                if rechecked.artifact:
                    raise PermissionError("known_malicious_artifact")
                raise PermissionError("ADR file protection blocked this command")
            self.store.execute("UPDATE environment_runs SET state='running' WHERE id=?", (identifier,))
            result = self.native.call(
                "environment_execute",
                {
                    "ids": [row["id"] for row in entries],
                    "protection_environment_ids": [
                        row["id"] for row in self.entries() if row["state"] == "active"
                    ],
                    "protection_service_ids": [
                        row["id"] for row in self.broker.credentials() if row["state"] == "active"
                    ],
                    "command": command,
                    "cwd": str(directory),
                    "timeout_seconds": timeout_seconds,
                },
                timeout=timeout_seconds + 5,
            )
            current = self.grants.active(grant["id"])
            if not current or not {row["id"] for row in entries} <= {
                row["id"] for row in self.permitted(current)
            }:
                raise PermissionError("Access was revoked; the command result was discarded")
            # Native output is already filtered. Also withhold recognizable
            # unrelated credential formats returned by the invoked service.
            if detect_credentials(result):
                result = {
                    "exit_code": result.get("exit_code"),
                    "stdout": "",
                    "stderr": "",
                    "output_withheld": True,
                    "message": "Output contained a possible credential and was withheld",
                }
            self.store.execute(
                "UPDATE environment_runs SET state='finished',exit_code=? WHERE id=?",
                (result.get("exit_code"), identifier),
            )
            self.store.audit("environment_used", "Ran a credential-backed command", {"run_id": identifier})
            return {"run_id": identifier, **result}
        except Exception as error:
            self.store.execute("UPDATE environment_runs SET state='failed' WHERE id=?", (identifier,))
            # Keep a receipt on known execution errors too. No command/result is
            # retained, and callers still receive the same exception/status.
            if isinstance(error, (ValueError, PermissionError, NativeUnavailable)):
                error.adr_run_id = identifier
            raise
        finally:
            self.slots.release()
