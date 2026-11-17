from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

ALLOWED_TOOLS = frozenset({"nmap", "httpx", "nuclei", "nikto", "amass", "subfinder"})
BLOCKED_PUBLIC_HOSTS = frozenset({
    "google.com", "microsoft.com", "cloudflare.com",
})


def hostname_from_target(target: str) -> str:
    value = target.strip()
    host = urlparse(value).hostname if "://" in value else value.split("/")[0].split(":")[0]
    if not host:
        raise ValueError("Target does not contain a hostname or IP address")
    return host.lower().rstrip(".")


def is_private_or_loopback(host: str) -> bool:
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = list({ipaddress.ip_address(info[4][0]) for info in infos})
        except (OSError, ValueError):
            return host in {"localhost", "localhost.localdomain"}
    return bool(addresses) and all(
        address.is_private or address.is_loopback or address.is_link_local
        for address in addresses
    )


def _is_blocked_host(host: str) -> bool:
    return any(host == blocked or host.endswith("." + blocked) for blocked in BLOCKED_PUBLIC_HOSTS)


def _authorized_targets() -> set[str]:
    raw = os.environ.get("UQOS_AUTHORIZED_TARGETS", "")
    return {item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()}


def authorize(tool: str, target: str, execute: bool) -> dict:
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool not allowlisted: {tool}")
    host = hostname_from_target(target)
    if _is_blocked_host(host):
        raise PermissionError(f"Target is blocked by default: {host}")
    if not execute:
        return {"authorized": True, "mode": "dry-run", "reason": "No active execution requested."}
    if is_private_or_loopback(host):
        return {"authorized": True, "mode": "active", "reason": "Private, loopback, or link-local target."}

    if not os.environ.get("UQOS_AUTH_TOKEN"):
        raise PermissionError("Active public-target execution requires UQOS_AUTH_TOKEN.")
    if host not in _authorized_targets():
        raise PermissionError(
            "Public target is not in UQOS_AUTHORIZED_TARGETS. Add the exact authorized hostname."
        )
    return {
        "authorized": True,
        "mode": "active",
        "reason": "Operator supplied token and exact target-scope allowlist entry.",
        "scope_host": host,
    }
