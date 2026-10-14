import time

import pytest
from conftest import add_credential

from adr_desktop.vault.broker import path_allowed, validate_origin, validate_path, validate_profile


@pytest.mark.parametrize(
    "origin",
    [
        "http://api.github.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://api.github.com/path",
        "https://api.github.com?x=1",
        "https://user:secret@api.github.com",
        "https://api.github.com:8443",
    ],
)
def test_invalid_destinations_are_rejected(origin):
    with pytest.raises(ValueError):
        validate_origin(origin)


@pytest.mark.parametrize(
    "path",
    [
        "//evil.example",
        "https://evil.example",
        "/repos/../secret",
        "/repos/%2e%2e/secret",
        "/repos%2fsecret",
        "/repos\\secret",
        "/repos\r\nInjected: bad",
        "/repos#fragment",
    ],
)
def test_request_path_cannot_override_destination_or_scope(path):
    with pytest.raises(ValueError):
        validate_path(path)


def test_allowed_prefix_is_a_path_segment_boundary():
    assert path_allowed("/repos/a/b?per_page=10", ["/repos"])
    assert not path_allowed("/repositories", ["/repos"])
    assert not path_allowed("/user", ["/repos"])


@pytest.mark.parametrize(
    "header", ["Host", "Cookie", "Content-Length", "Proxy-Authorization", "Bad\r\nHeader"]
)
def test_credential_cannot_control_http_routing_headers(header):
    with pytest.raises(ValueError):
        validate_profile(
            {
                "name": "Test",
                "origin": "https://api.github.com",
                "auth_type": "api_key",
                "header_name": header,
                "allowed_paths": ["/user"],
            }
        )


def connection(vault, credential, name="Agent"):
    return vault.grants.issue([credential["id"]], kind="legacy", project="/workspace", approval_mode="ask",
                              name=name)


def test_expired_requests_cannot_be_approved(vault):
    credential = add_credential(vault)
    grant = connection(vault, credential)
    pending = vault.broker.enqueue(grant, credential["id"], "/user")
    vault.store.execute(
        "UPDATE broker_requests SET expires_at=? WHERE id=?", (time.time() - 1, pending["request_id"])
    )
    with pytest.raises(ValueError):
        vault.broker.approve(pending["request_id"], True)
    assert not any(operation == "vault_perform" for operation, _ in vault.native.calls)


def test_credential_revocation_blocks_pending_requests(vault):
    credential = add_credential(vault)
    grant = connection(vault, credential)
    pending = vault.broker.enqueue(grant, credential["id"], "/user")
    vault.broker.remove(credential["id"])
    assert vault.broker.result(grant, pending["request_id"])["state"] == "revoked"
    with pytest.raises(ValueError):
        vault.broker.approve(pending["request_id"], True)


def test_approval_result_belongs_only_to_requesting_connection(vault):
    credential = add_credential(vault)
    first = connection(vault, credential, "First")
    second = connection(vault, credential, "Second")
    pending = vault.broker.enqueue(first, credential["id"], "/user")
    with pytest.raises(ValueError):
        vault.broker.result(second, pending["request_id"])


def test_no_plaintext_fallback_without_native_host(vault):
    vault.native.connected = False
    with pytest.raises(RuntimeError):
        add_credential(vault)
    assert vault.broker.credentials() == []


def test_requests_of_a_revoked_grant_can_no_longer_be_approved(vault):
    credential = add_credential(vault)
    grant = connection(vault, credential)
    pending = vault.broker.enqueue(grant, credential["id"], "/user")
    vault.broker.revoke_requests(grant["id"])
    assert vault.broker.result(grant, pending["request_id"])["state"] == "revoked"
    with pytest.raises(ValueError):
        vault.broker.approve(pending["request_id"], True)
    assert not any(operation == "vault_perform" for operation, _ in vault.native.calls)
