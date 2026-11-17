from __future__ import annotations
import ipaddress, os, socket
from urllib.parse import urlparse

ALLOWED_TOOLS=frozenset({"nmap","httpx","nuclei","nikto","amass","subfinder"})
BLOCKED_PUBLIC_HOSTS=frozenset({"google.com","www.google.com","microsoft.com","www.microsoft.com","cloudflare.com","www.cloudflare.com"})

def hostname_from_target(target:str)->str:
    value=target.strip()
    host=urlparse(value).hostname if "://" in value else value.split("/")[0].split(":")[0]
    if not host:
        raise ValueError("Target does not contain a hostname or IP address")
    return host.lower().rstrip(".")

def is_private_or_loopback(host:str)->bool:
    try:
        addr=ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        try:
            addr=ipaddress.ip_address(socket.gethostbyname(host))
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except OSError:
            return host in {"localhost","localhost.localdomain"}

def authorize(tool:str,target:str,execute:bool)->dict:
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool not allowlisted: {tool}")
    host=hostname_from_target(target)
    if host in BLOCKED_PUBLIC_HOSTS:
        raise PermissionError(f"Target is blocked by default: {host}")
    if not execute:
        return {"authorized":True,"mode":"dry-run","reason":"No active execution requested."}
    if is_private_or_loopback(host):
        return {"authorized":True,"mode":"active","reason":"Private, loopback, or link-local target."}
    if not os.environ.get("UQOS_AUTH_TOKEN"):
        raise PermissionError("Active execution against a public target requires UQOS_AUTH_TOKEN.")
    return {"authorized":True,"mode":"active","reason":"Explicit authorization token supplied."}
