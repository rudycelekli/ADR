"""Owner-managed artifact intelligence, bounded local checks, and denial receipts."""

import copy
import json
import threading
from collections import OrderedDict

from .config import utcnow
from .detection.inline.feed.api_v1 import (
    BUNDLED_FEED_ID,
    compile_generation,
    compose_generation,
    generation_summary,
    parse_feed_json,
    validate_generation,
)
from .detection.inline.installed import MAX_SCAN_PROJECTS, empty_scan, scan_installed
from .detection.operation import printable
from .integrations import agents
from .storage.files import canonical
from .threat_feed import load_bundled_feed

MAX_POLICY_BYTES = 1024 * 1024
SCAN_STATES = frozenset({"not_run", "complete", "partial", "error"})


class ThreatStateConflict(ValueError):
    """The owner must refresh rather than overwriting another policy edit."""


def initialize_threats(previous):
    """Refresh the bundled baseline while retaining validated owner additions."""
    enabled, imported_at, old_generation = True, None, None
    if previous is not None:
        if (
            not isinstance(previous, dict)
            or set(previous) != {"enabled", "generation", "imported_at"}
            or type(previous["enabled"]) is not bool
            or (previous["imported_at"] is not None and not isinstance(previous["imported_at"], str))
        ):
            raise ValueError("The saved artifact blocking settings are invalid; they were not replaced")
        old_generation = validate_generation(previous["generation"])
        enabled, imported_at = previous["enabled"], previous["imported_at"]
    custom = old_generation["feeds"][1] if old_generation and len(old_generation["feeds"]) == 2 else None
    try:
        baseline = load_bundled_feed()
        generation = compose_generation(baseline, custom)
    except (OSError, ValueError):
        if old_generation is None:
            raise ValueError(
                "The bundled threat list could not be validated; no policy was replaced"
            ) from None
        return {
            "enabled": enabled, "generation": old_generation, "imported_at": imported_at,
        }, "The updated bundled list could not be applied. The last accepted list is still in use."
    return {
        "enabled": enabled, "generation": generation, "imported_at": imported_at,
    }, None


def _display(value, maximum=8192):
    return printable(str(value))[:maximum]


class ThreatProtection:
    def __init__(self, runtime):
        self.runtime = runtime
        self.store = runtime.store
        self.check_lock = threading.Lock()
        self.generations_lock = threading.Lock()
        self.generations = OrderedDict()
        self.remember_generation(runtime.policy["threats"]["generation"])

    def remember_generation(self, generation, *, compiled=None):
        compiled = compiled or compile_generation(generation)
        with self.generations_lock:
            self.generations[compiled.digest] = compiled
            self.generations.move_to_end(compiled.digest)
            while len(self.generations) > 8:
                self.generations.popitem(last=False)

    def _snapshot(self):
        with self.runtime.policy_lock:
            return self.runtime.policy["revision"], copy.deepcopy(self.runtime.policy["threats"])

    def _check_revision(self, expected):
        if expected != self.runtime.policy["revision"]:
            raise ThreatStateConflict("Protection settings changed. Refresh and review the change again.")

    def _publish(self, config):
        updated = copy.deepcopy(self.runtime.policy)
        updated["threats"] = config
        # Leave room for the revision replaced by _publish_policy. Never publish
        # an authority that the bounded offline hook cannot subsequently read.
        if len(canonical(updated).encode()) > MAX_POLICY_BYTES - 128:
            raise ValueError("The combined protection policy is too large")
        self.runtime._publish_policy(updated)

    def change_settings(self, *, enabled, expected_revision):
        if type(enabled) is not bool:
            raise ValueError("Choose whether artifact blocking is enabled")
        with self.runtime.policy_lock:
            self._check_revision(expected_revision)
            updated = copy.deepcopy(self.runtime.policy["threats"])
            updated["enabled"] = enabled
            self._publish(updated)
        self.store.audit(
            "threat_protection_changed",
            "Known-malicious artifact blocking enabled" if enabled
            else "Known-malicious artifact blocking disabled",
        )
        return self.status()

    def _import_candidate(self, document, expected_revision):
        custom = parse_feed_json(document)
        with self.runtime.policy_lock:
            self._check_revision(expected_revision)
            current = copy.deepcopy(self.runtime.policy["threats"])
        generation = compose_generation(current["generation"]["feeds"][0], custom)
        return custom, generation, current

    def preview_import(self, document, *, expected_revision):
        custom, generation, current = self._import_candidate(document, expected_revision)
        summary = generation_summary(generation)
        metadata = next(item for item in summary["feeds"] if item["feed_id"] == custom["feed_id"])
        return {
            "feed_id": custom["feed_id"], "revision": custom["revision"],
            "active_indicators": metadata["active"], "revoked_indicators": metadata["revoked"],
            "all_versions_count": sum(
                item["status"] == "active" and item["target"].get("all_versions") is True
                for item in custom["indicators"]
            ),
            "counts": {key: summary[key] for key in (
                "file_sha256", "skill_sha256", "npm", "pypi", "mcp_endpoint", "package_versions", "total",
            )},
            "replaces_custom": len(current["generation"]["feeds"]) == 2,
            "expected_revision": expected_revision,
        }

    def import_feed(self, document, *, expected_revision, confirm=False):
        if confirm is not True:
            raise ValueError("Review and confirm the local threat-list import")
        custom, generation, _ = self._import_candidate(document, expected_revision)
        with self.runtime.policy_lock:
            self._check_revision(expected_revision)
            updated = copy.deepcopy(self.runtime.policy["threats"])
            updated.update(generation=generation, imported_at=utcnow())
            self._publish(updated)
        self.store.audit(
            "threat_list_imported", "Imported an owner-selected local threat list",
            {"feed_id": custom["feed_id"], "revision": custom["revision"]},
        )
        return self.status()

    def _scan(self):
        row = self.store.one("SELECT payload FROM artifact_scan WHERE id=1")
        if not row:
            return empty_scan()
        value = json.loads(row["payload"])
        if value.get("state") not in SCAN_STATES:
            return empty_scan()
        return value

    def summary(self):
        revision, config = self._snapshot()
        scan = self._scan()
        return {
            "revision": revision, "enabled": config["enabled"],
            "generation": config["generation"]["digest"],
            "latest_block_id": (
                self.store.one("SELECT id FROM artifact_blocks ORDER BY id DESC LIMIT 1") or {"id": 0}
            )["id"],
            "scan_revision": scan.get("checked_at"),
        }

    def status(self):
        revision, config = self._snapshot()
        summary = generation_summary(config["generation"])
        warning = getattr(self.runtime, "threat_feed_warning", None)
        scan = self._scan()
        scan["stale"] = bool(scan["generation"] and scan["generation"] != summary["digest"])
        return {
            "enabled": config["enabled"], "revision": revision,
            "feed": {
                "state": "degraded" if warning else "ready" if summary["total"] else "empty",
                "generation": summary["digest"],
                "counts": {key: summary[key] for key in (
                    "file_sha256", "skill_sha256", "npm", "pypi", "mcp_endpoint", "package_versions", "total",
                )},
                "feeds": [{
                    "feed_id": item["feed_id"], "revision": item["revision"],
                    "published_at": item["published_at"],
                    "active_indicators": item["active"], "revoked_indicators": item["revoked"],
                } for item in summary["feeds"]],
                "imported_at": config["imported_at"],
                "has_custom": any(item["feed_id"] != BUNDLED_FEED_ID for item in summary["feeds"]),
                "error": warning,
            },
            "scan": scan,
            "blocks": self.store.rows("SELECT * FROM artifact_blocks ORDER BY id DESC LIMIT 25"),
        }

    def record_block(self, decision, *, harness, source):
        """Accept only actual denials with metadata from a recently accepted feed."""
        if isinstance(decision, dict):
            denied, artifact = decision.get("decision") == "deny", decision.get("artifact")
            session, tool = decision.get("session_id", ""), decision.get("tool", "")
        else:
            denied, artifact = decision.decision == "deny", decision.artifact
            session, tool = decision.session_id, decision.tool
        if not denied or not isinstance(artifact, dict) or source not in {"hook", "approval", "vault"}:
            return False
        # A newly published offline policy can be read immediately by a hook.
        # Wait for the publication transaction to finish registering its index.
        with self.runtime.policy_lock, self.generations_lock:
            compiled = self.generations.get(artifact.get("generation"))
        record = compiled.catalog().get(artifact.get("indicator_id")) if compiled else None
        if not record or any(
            artifact.get(key) != record[key] for key in ("source_id", "kind", "target_display")
        ):
            return False
        # Store the verified feed label, not a hook-supplied command/config value.
        self.store.execute(
            """INSERT INTO artifact_blocks(
               timestamp,harness,session_id,tool,indicator_id,source_id,kind,generation,target_display,source
               ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (utcnow(), _display(harness, 40), _display(session, 512), _display(tool, 200),
             record["indicator_id"], record["source_id"], record["kind"], compiled.digest,
             record["target_display"], source),
        )
        return True

    def _persist_scan(self, result):
        self.store.execute(
            "INSERT INTO artifact_scan(id,payload) VALUES (1,?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            (canonical(result),),
        )

    def check_installed(self):
        """Inspect known local roots and inventory candidates, without starting them."""
        if not self.check_lock.acquire(blocking=False):
            raise ThreatStateConflict("An installed-item check is already running")
        try:
            _, config = self._snapshot()
            projects = [row["project"] for row in self.store.rows(
                "SELECT DISTINCT project FROM sessions WHERE project<>'' ORDER BY project LIMIT ?",
                (MAX_SCAN_PROJECTS + 1,),
            )]
            result = scan_installed(
                config["generation"], self.store.settings().get("inventory_snapshot", {}), projects, agents,
                checked_at=utcnow(),
            )
            self._persist_scan(result)
            return self.status()
        finally:
            self.check_lock.release()
