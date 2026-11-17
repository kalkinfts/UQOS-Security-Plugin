import os
import pytest
from uqos_safeguards import authorize, hostname_from_target


def test_local_dry_run_allowed():
    result = authorize("nmap", "127.0.0.1", False)
    assert result["mode"] == "dry-run"


def test_public_active_target_requires_token_and_scope(monkeypatch):
    monkeypatch.delenv("UQOS_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("UQOS_AUTHORIZED_TARGETS", raising=False)
    with pytest.raises(PermissionError, match="UQOS_AUTH_TOKEN"):
        authorize("nmap", "example.com", True)

    monkeypatch.setenv("UQOS_AUTH_TOKEN", "operator-supplied")
    with pytest.raises(PermissionError, match="UQOS_AUTHORIZED_TARGETS"):
        authorize("nmap", "example.com", True)

    monkeypatch.setenv("UQOS_AUTHORIZED_TARGETS", "example.com")
    result = authorize("nmap", "https://example.com", True)
    assert result["authorized"] is True
    assert result["scope_host"] == "example.com"


def test_blocked_provider_subdomains(monkeypatch):
    monkeypatch.setenv("UQOS_AUTH_TOKEN", "operator-supplied")
    monkeypatch.setenv("UQOS_AUTHORIZED_TARGETS", "foo.google.com")
    with pytest.raises(PermissionError, match="blocked by default"):
        authorize("nmap", "foo.google.com", True)


def test_hostname_parser():
    assert hostname_from_target("https://example.com/path") == "example.com"


def test_unknown_tool_is_rejected():
    with pytest.raises(ValueError, match="not allowlisted"):
        authorize("unknown", "127.0.0.1", False)
