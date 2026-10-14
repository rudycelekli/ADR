"""ADR Discovery's public interface. Code outside this package imports Discovery only from here."""

from __future__ import annotations

from importlib.resources import files

from .catalog.load import Catalog, loads
from .coverage.ledger import Ledger
from .coverage.report import coverage_page, summarize_coverage
from .judge import Policy
from .pipeline import discover
from .reporter import to_json
from .reporter.snapshot import from_dict
from .world.budget import Budget
from .world.gate import Gate
from .world.platform import for_host

__all__ = [
    "Budget", "Gate", "Ledger", "Policy", "bundled_catalog", "coverage_page", "discover", "for_host",
    "from_dict", "summarize_coverage", "to_json",
]


def bundled_catalog() -> Catalog:
    """The catalog that ships with this package, validated at load."""
    return loads(files("adr_discovery.catalog").joinpath("catalog.json").read_text(encoding="utf-8"))
