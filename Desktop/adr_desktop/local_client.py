"""Bounded loopback-only client. It never follows redirects or reads proxy settings."""

import http.client
import json
import re
from pathlib import Path

from .storage.files import read_private_json
from .vault.contracts import SAFE_ERRORS


class LocalUnavailable(RuntimeError):
    def __init__(self, message, *, run_id=""):
        super().__init__(message)
        self.run_id = run_id if isinstance(run_id, str) and re.fullmatch(r"[a-f0-9]{32}", run_id) else ""


def request(state_dir: Path, method: str, path: str, *, token="", payload=None, timeout=3.0):
    runtime = read_private_json(state_dir / "runtime.json", maximum=16384)
    port = runtime.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise LocalUnavailable("ADR has no valid local listener")
    if not path.startswith("/api/") or "\r" in path or "\n" in path:
        raise ValueError("Invalid local API path")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    encoded = json.dumps(payload, allow_nan=False).encode() if payload is not None else None
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        body = response.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise LocalUnavailable("ADR response exceeded its local limit")
        if response.status >= 300:
            # Never reflect arbitrary server/validation text into a model result.
            # Only known credential-availability codes have actionable messages.
            try:
                error = json.loads(body)
                code = error.get("detail")
                message = SAFE_ERRORS.get(code) if isinstance(code, str) else None
                run_id = error.get("run_id", "") if path == "/api/agent/environment/run" else ""
            except (ValueError, AttributeError):
                message, run_id = None, ""
            raise LocalUnavailable(
                message or f"ADR rejected the request (HTTP {response.status})", run_id=run_id,
            )
        return json.loads(body) if body else {}
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise LocalUnavailable("ADR Desktop is unavailable; open the menu-bar app") from exc
    finally:
        connection.close()
