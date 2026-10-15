"""Frontmatter metadata reaches the asset: tools, model, version.

The extractor has always read these keys; until they are on the asset they
are collected and thrown away, and a skill that may run `Bash` looks the
same as one that may only read.
"""

from __future__ import annotations

import json

from adr_discovery.contracts.records import Kind
from adr_discovery.extractor.formats.frontmatter import parse
from adr_discovery.pipeline import discover
from adr_discovery.reporter import to_json
from adr_discovery.reporter.snapshot import from_dict


def _by_kind(world, catalog, kind):
    return [a for a in discover(world.gate(), catalog).assets if a.kind is kind]


def test_a_skill_carries_its_tools_model_and_version(world, catalog):
    world.file("/home/a/.claude/skills/s/SKILL.md",
               "---\nname: s\nallowed-tools: Bash(git:*), Read\nmodel: opus\nversion: 1.10\n---\nbody\n")

    (skill,) = _by_kind(world, catalog, Kind.SKILL)

    assert skill.allowed_tools == ("Bash(git:*)", "Read")
    assert skill.model == "opus"
    assert skill.version == "1.10"


def test_commands_agents_and_output_styles_carry_them_too(world, catalog):
    world.file("/home/a/.claude/commands/c.md", "---\nallowed-tools:\n  - Read\nversion: '2'\n---\n")
    world.file("/home/a/.claude/agents/g.md", "---\nname: g\ntools: [Grep, Glob]\nmodel: sonnet\n---\n")
    world.file("/home/a/.claude/output-styles/o.md", "---\nname: o\nversion: 3\n---\n")

    (command,) = _by_kind(world, catalog, Kind.COMMAND)
    (agent,) = _by_kind(world, catalog, Kind.AGENT_DEFINITION)
    (style,) = _by_kind(world, catalog, Kind.OUTPUT_STYLE)

    assert command.allowed_tools == ("Read",) and command.version == "2"
    assert agent.allowed_tools == ("Grep", "Glob") and agent.model == "sonnet"
    assert style.version == "3" and style.allowed_tools == () and style.model is None


def test_a_skill_without_frontmatter_has_none(world, catalog):
    world.file("/home/a/.claude/skills/s/SKILL.md", "# just prose\n")

    (skill,) = _by_kind(world, catalog, Kind.SKILL)

    assert (skill.allowed_tools, skill.model, skill.version) == ((), None, None)


def test_version_is_kept_as_written():
    assert parse("---\nversion: 1.10\n---\n")["version"] == "1.10"
    assert parse("---\nversion: \"0.9.0\"\n---\n")["version"] == "0.9.0"


def test_the_metadata_survives_a_round_trip(world, catalog):
    world.file("/home/a/.claude/skills/s/SKILL.md", "---\nname: s\nallowed-tools: Read\nmodel: haiku\n---\n")
    snapshot = discover(world.gate(), catalog)

    (skill,) = [a for a in from_dict(json.loads(to_json(snapshot))).assets if a.kind is Kind.SKILL]

    assert skill.allowed_tools == ("Read",) and skill.model == "haiku"
