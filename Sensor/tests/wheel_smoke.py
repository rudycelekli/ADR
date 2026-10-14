"""Run with python -I in a clean wheel-only environment, outside the checkout."""

import importlib.util
import json
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

import adr_discovery
import adr_sensor
from adr_discovery import api as discovery
from adr_sensor import api as sensor


def command(name, *arguments):
    script = Path(sysconfig.get_path("scripts")) / name
    return subprocess.run([str(script), *arguments], capture_output=True, text=True, timeout=120)


def main():
    prefix = Path(sys.prefix).resolve()
    for package in (adr_sensor, adr_discovery, sensor, discovery):
        assert Path(package.__file__).resolve().is_relative_to(prefix), f"{package.__name__} is not from the wheel"
    for name in ("adr_desktop", "fastapi"):
        assert importlib.util.find_spec(name) is None, f"Unexpected host dependency: {name}"
    catalog = discovery.bundled_catalog()
    assert len(catalog), "The Discovery catalog did not load from the wheel"
    version = command("adr-sensor", "--version")
    assert version.returncode == 0, version.stderr
    with tempfile.TemporaryDirectory() as root:
        scan = command("adr-discovery", "--root", root, "--dry-run", "--json")
    # An empty fixture tree is a partial scan (exit code 2) that still prints its snapshot.
    assert scan.returncode in (0, 2), scan.stderr
    assert json.loads(scan.stdout)["catalog_version"] == catalog.version
    print("Sensor wheel: both packages, both commands and the Discovery catalog passed.")


if __name__ == "__main__":
    main()
