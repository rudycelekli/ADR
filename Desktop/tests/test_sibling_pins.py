"""Desktop takes some dependencies from sibling folders; each pin must equal that folder's version."""

import re
import tomllib
from pathlib import Path

DESKTOP = Path(__file__).resolve().parents[1]


def pyproject(folder):
    return tomllib.loads((folder / "pyproject.toml").read_text(encoding="utf-8"))


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def test_sibling_folder_dependencies_are_pinned_to_the_folder_version():
    desktop = pyproject(DESKTOP)
    requirements = list(desktop["project"]["dependencies"])
    for extra in desktop["project"].get("optional-dependencies", {}).values():
        requirements.extend(extra)
    pins = {}
    for requirement in requirements:
        name = re.match(r"[A-Za-z0-9._-]+", requirement)[0]
        exact = re.fullmatch(r"[A-Za-z0-9._-]+\s*==\s*([^\s;,]+)", requirement)
        pins[normalized(name)] = exact[1] if exact else requirement
    siblings = {}
    for source in desktop["tool"]["uv"]["sources"].values():
        if "path" in source:
            sibling = pyproject(DESKTOP / source["path"])["project"]
            siblings[normalized(sibling["name"])] = sibling["version"]
    assert {name: pins.get(name) for name in siblings} == siblings
