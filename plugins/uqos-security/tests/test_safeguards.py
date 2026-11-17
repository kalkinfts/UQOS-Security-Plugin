import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from uqos_safeguards import authorize,hostname_from_target

def test_local_target_is_allowed_in_dry_run():
    assert authorize("nmap","127.0.0.1",False)["authorized"] is True

def test_public_target_requires_token(monkeypatch):
    monkeypatch.delenv("UQOS_AUTH_TOKEN",raising=False)
    try: authorize("nmap","8.8.8.8",True)
    except PermissionError: return
    raise AssertionError("public active target should require authorization")

def test_hostname_parser():
    assert hostname_from_target("https://example.com/path")=="example.com"
