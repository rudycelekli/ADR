"""Selects the reviewed baseline feed for Desktop. Validation and matching live in detection's feed engine.

Policy authority remains with the host; importing this module never scans or
opens this application's profile.
"""

from pathlib import Path

from .detection.inline import feed
from .detection.inline.feed.api_v1 import MAX_FEED_BYTES, parse_feed_json

__all__ = ["load_bundled_feed"]


def load_bundled_feed():
    """Load only the application-owned baseline, never a user-specified path."""
    path = Path(feed.__file__).parent / "malicious_artifacts.json"
    with path.open("rb") as handle:
        return parse_feed_json(handle.read(MAX_FEED_BYTES + 1))
