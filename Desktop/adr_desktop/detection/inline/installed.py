"""Installed-item checks: agents' configured MCP servers and skills, matched against the artifact feed.

Bounded local reads only. Nothing is started, installed or blocked; Desktop saves and shows the result.
"""

import hashlib
import os
from collections import Counter
from pathlib import Path

from ...storage.files import canonical
from ..operation import display
from ..ports import AgentConfig
from .artifacts import (
    IdentityBudget,
    configured_mcp_definitions,
    inspect_file,
    inspect_mcp_definition,
    skill_roots,
)
from .feed.api_v1 import compile_generation

HARNESS_NAMES = ("claude", "codex", "opencode", "copilot")
MAX_SCAN_ITEMS = 512
MAX_SCAN_FINDINGS = 100
MAX_SCAN_PROJECTS = 24
MAX_SCAN_ROOTS = 128


def empty_scan():
    return {
        "state": "not_run", "checked_at": None, "generation": None, "stale": False,
        "checked_items": 0, "skipped_items": 0, "findings": [], "issues": [],
    }


def scan_installed(generation, inventory, session_projects, agents: AgentConfig, *, checked_at):
    """Inspect known local roots and inventory candidates, without starting them.

    ``inventory`` is the saved inventory snapshot and ``session_projects`` the captured projects; the
    home folder is always checked. Returns the scan record, which is partial when a limit was reached.
    """
    compiled = compile_generation(generation)
    result = empty_scan()
    result.update(state="complete", generation=compiled.digest, checked_at=checked_at)
    issues, checked, findings, associations = Counter(), set(), {}, {}
    budget = IdentityBudget(seconds=4, max_files=512, max_total_bytes=32 * 1024 * 1024)
    assets = inventory.get("assets", []) if isinstance(inventory, dict) else []
    assets = assets if isinstance(assets, list) else []
    if len(assets) > 2000:
        issues["inventory_limit"] += 1
    assets = [item for item in assets[:2000] if isinstance(item, dict)]

    def consume(evidence, *, label=None, inventory_asset_id=None):
        issues.update(evidence.unresolved)
        for candidate in evidence.candidates:
            display_label = display(label or candidate.label, 200)
            checked.add((candidate.location, display_label))
            for match in compiled.match(candidate.subject):
                key = canonical([match["indicator_id"], candidate.location, display_label])
                if len(findings) >= MAX_SCAN_FINDINGS and key not in findings:
                    issues["finding_limit"] += 1
                    continue
                links = associations.setdefault(key, set())
                if inventory_asset_id:
                    links.add(inventory_asset_id)
                findings[key] = {
                    "id": hashlib.sha256(key.encode()).hexdigest()[:32],
                    **{field: match[field] for field in (
                        "indicator_id", "source_id", "kind", "target_display",
                        "summary", "references",
                    )},
                    "location": display(candidate.location), "label": display_label,
                    "inventory_asset_id": next(iter(links)) if len(links) == 1 else None,
                }

    projects = [str(Path.home())]
    projects.extend(project for project in session_projects if Path(project).is_absolute())
    projects = list(dict.fromkeys(projects))
    if len(projects) > MAX_SCAN_PROJECTS:
        issues["project_limit"] += 1
    projects = projects[:MAX_SCAN_PROJECTS]

    seen_configs = set()
    for project in projects:
        for harness in HARNESS_NAMES:
            try:
                budget.check()
            except ValueError:
                issues["check_limit"] += 1
                break
            diagnostics = []
            definitions = configured_mcp_definitions(
                harness, project, agents, budget=budget, diagnostics=diagnostics,
            )
            issues.update(diagnostics)
            for alias, definition, path in definitions:
                # Disabled entries are findings about configuration, not live use.
                key = (str(path), alias, canonical(definition), project)
                if key in seen_configs:
                    continue
                seen_configs.add(key)
                consume(
                    inspect_mcp_definition(definition, path, project, budget=budget),
                    label=f"{alias} · {harness}",
                )

    roots = []
    for project in projects:
        for harness in HARNESS_NAMES:
            roots.extend(skill_roots(harness, project))
    files = {}

    def add_manifest(manifest, asset_id=None):
        try:
            canonical_path = Path(manifest).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            issues["file_unresolved"] += 1
            return
        # Coalesce aliases such as macOS /var and /private/var before
        # associating findings with a unique inventory record.
        identifiers = files.setdefault(canonical_path, set())
        if isinstance(asset_id, str) and asset_id:
            identifiers.add(asset_id)

    for asset in assets:
        path = asset.get("install_path") or asset.get("path")
        if not isinstance(path, str) or not Path(path).is_absolute():
            continue
        if asset.get("kind") == "skill":
            manifest = Path(path) if Path(path).name == "SKILL.md" else Path(path) / "SKILL.md"
            add_manifest(manifest, asset.get("asset_id"))
        elif asset.get("kind") == "plugin":
            roots.append(Path(path) / "skills")
    roots = list(dict.fromkeys(roots))
    if len(roots) > MAX_SCAN_ROOTS:
        issues["root_limit"] += 1
    # Explicit roots, at most one hidden grouping directory; never a
    # recursive device walk or a scan of arbitrary package dependencies.
    for root in roots[:MAX_SCAN_ROOTS]:
        if len(files) >= MAX_SCAN_ITEMS:
            issues["item_limit"] += 1
            break
        try:
            budget.check()
            with os.scandir(root) as entries:
                for index, entry in enumerate(entries):
                    if index >= MAX_SCAN_ITEMS or len(files) >= MAX_SCAN_ITEMS:
                        issues["item_limit"] += 1
                        break
                    budget.check()
                    if entry.is_dir(follow_symlinks=False):
                        manifest = Path(entry.path) / "SKILL.md"
                        if manifest.is_file():
                            add_manifest(manifest)
                        elif entry.name.startswith("."):
                            with os.scandir(entry.path) as hidden:
                                for child_index, child in enumerate(hidden):
                                    if child_index >= MAX_SCAN_ITEMS or len(files) >= MAX_SCAN_ITEMS:
                                        issues["item_limit"] += 1
                                        break
                                    budget.check()
                                    if child.is_dir(follow_symlinks=False):
                                        nested = Path(child.path) / "SKILL.md"
                                        if nested.is_file():
                                            add_manifest(nested)
                    elif entry.is_symlink():
                        issues["skill_symlink_not_enumerated"] += 1
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            issues["skill_root_unreadable"] += 1
    if len(files) > MAX_SCAN_ITEMS:
        issues["item_limit"] += len(files) - MAX_SCAN_ITEMS
    for manifest, identifiers in list(files.items())[:MAX_SCAN_ITEMS]:
        try:
            budget.check()
        except ValueError:
            issues["check_limit"] += 1
            break
        unique = set(value for value in identifiers if isinstance(value, str) and value)
        consume(
            inspect_file(manifest, skill=True, budget=budget),
            label=manifest.parent.name,
            inventory_asset_id=next(iter(unique)) if len(unique) == 1 else None,
        )
    result.update(
        state="partial" if issues else "complete",
        checked_items=len(checked), skipped_items=sum(issues.values()),
        findings=list(findings.values()),
        issues=[{"reason": reason, "count": count} for reason, count in sorted(issues.items())],
    )
    return result
