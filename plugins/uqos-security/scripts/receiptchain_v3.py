"""ReceiptChain v3: fail-closed execution receipts, fenced leases and RFC 6962 proofs.

Cryptographic attestation and checkpoint signatures are delegated to mandatory
trusted verifier callbacks. This module never treats simulated quote fields as
hardware evidence. The callback must parse the signed quote bytes and validate
the vendor certificate chain, signatures, TCB status and quote structure.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

GENESIS = "RC-GENESIS::v3"
DOMAIN_LEAF = b"\x00"
DOMAIN_NODE = b"\x01"
MAX_SAFE_INTEGER = (1 << 53) - 1


class ReceiptError(ValueError):
    pass


def _validate_json(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ReceiptError("Integers outside the interoperable IEEE-754 safe range must be strings")
        return
    if isinstance(value, float):
        raise ReceiptError("This receipt profile forbids floats; encode exact quantities as strings or safe integers")
    if isinstance(value, list):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ReceiptError("JSON object keys must be strings")
        for item in value.values():
            _validate_json(item)
        return
    raise ReceiptError(f"Unsupported JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Canonical UTF-8 JSON for the ReceiptChain integer-only JCS profile.

    Object keys are ordered by UTF-16 code units, matching RFC 8785. Floating
    point values are deliberately excluded to avoid cross-runtime ambiguity.
    """
    _validate_json(value)

    def quote(s: str) -> str:
        return json.dumps(s, ensure_ascii=False, separators=(",", ":"))

    def encode(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, str):
            return quote(v)
        if isinstance(v, list):
            return "[" + ",".join(encode(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v, key=lambda k: k.encode("utf-16-be", errors="surrogatepass"))
            return "{" + ",".join(quote(k) + ":" + encode(v[k]) for k in keys) + "}"
        raise ReceiptError("Unsupported canonical value")

    return encode(value).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return sha256(DOMAIN_LEAF + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(DOMAIN_NODE + left + right)


def _largest_power_of_two_less_than(n: int) -> int:
    if n < 2:
        raise ReceiptError("Merkle split requires at least two leaves")
    k = 1 << ((n - 1).bit_length() - 1)
    return k if k < n else k >> 1


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_less_than(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if index < 0 or index >= len(leaves):
        raise ReceiptError("Leaf index outside tree")
    if len(leaves) == 1:
        return []
    k = _largest_power_of_two_less_than(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def verify_inclusion(data: bytes, index: int, size: int, proof: Iterable[bytes], root: bytes) -> bool:
    if size <= 0 or index < 0 or index >= size:
        return False
    fn, sn = index, size - 1
    value = leaf_hash(data)
    for sibling in proof:
        if fn & 1 or fn == sn:
            value = node_hash(sibling, value)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            value = node_hash(value, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and value == root


@dataclass(frozen=True)
class AttestationPolicy:
    allowed_mrtd: frozenset[str]
    quote_verifier: Callable[[dict[str, Any]], dict[str, Any]]
    tcb_policy: Callable[[dict[str, Any]], bool]


def verify_attestation(binding: dict[str, Any], evidence: dict[str, Any],
                        policy: AttestationPolicy) -> dict[str, Any]:
    """Verify evidence through a trusted platform-specific quote verifier.

    quote_verifier MUST derive fields from the signed quote bytes and verify the
    vendor chain/signatures. Returned values are trusted only after that check.
    """
    required = {"quote", "collateral"}
    if not isinstance(evidence, dict) or not required.issubset(evidence):
        raise ReceiptError("Attestation evidence must include raw quote and collateral")
    expected = hashlib.sha512(b"ReceiptChain/TDX/report-data/v3\x00" + canonical_json(binding)).digest()
    verified = policy.quote_verifier(evidence)
    if not isinstance(verified, dict) or verified.get("verified") is not True:
        raise ReceiptError("Platform quote verification failed")
    report_data = verified.get("report_data")
    if not isinstance(report_data, (bytes, bytearray)) or bytes(report_data) != expected:
        raise ReceiptError("Quote report_data does not bind this run")
    mrtd = verified.get("mrtd")
    if not isinstance(mrtd, str) or mrtd not in policy.allowed_mrtd:
        raise ReceiptError("TD measurement is not allowlisted")
    if not policy.tcb_policy(verified):
        raise ReceiptError("TCB policy rejected the platform state")
    return {"mrtd": mrtd, "report_data_sha512": expected.hex(),
            "attestation_status": "verified-by-configured-platform-verifier"}


class ReceiptChain:
    """SQLite-backed receipt ledger with atomic fencing and RFC 6962 append log."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS leases(
                    run_id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                    fence INTEGER NOT NULL, expires_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs(
                    run_id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                    fence INTEGER NOT NULL, started_ns INTEGER NOT NULL,
                    closed INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS steps(
                    run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                    payload BLOB NOT NULL, step_hash TEXT NOT NULL,
                    PRIMARY KEY(run_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS receipts(
                    run_id TEXT PRIMARY KEY, fence INTEGER NOT NULL,
                    receipt BLOB NOT NULL, receipt_hash TEXT NOT NULL,
                    leaf_index INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS log_leaves(
                    leaf_index INTEGER PRIMARY KEY AUTOINCREMENT,
                    leaf BLOB NOT NULL
                );
            """)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def begin_run(self, run_id: str, owner: str, ttl_ms: int = 30_000) -> int:
        if not run_id or not owner or ttl_ms <= 0:
            raise ReceiptError("run_id, owner and positive ttl_ms are required")
        now = time.time_ns()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT fence, expires_ns FROM leases WHERE run_id=?", (run_id,)).fetchone()
            if old and old["expires_ns"] > now:
                db.rollback()
                raise ReceiptError("Run already has an unexpired lease")
            fence = (old["fence"] + 1) if old else 1
            expires = now + ttl_ms * 1_000_000
            db.execute("INSERT INTO leases(run_id,owner,fence,expires_ns) VALUES(?,?,?,?) "
                       "ON CONFLICT(run_id) DO UPDATE SET owner=excluded.owner,"
                       "fence=excluded.fence,expires_ns=excluded.expires_ns",
                       (run_id, owner, fence, expires))
            db.execute("INSERT INTO runs(run_id,owner,fence,started_ns,closed) VALUES(?,?,?,?,0) "
                       "ON CONFLICT(run_id) DO UPDATE SET owner=excluded.owner,"
                       "fence=excluded.fence,started_ns=excluded.started_ns,closed=0",
                       (run_id, owner, fence, now))
            db.commit()
            return fence

    def record_step(self, run_id: str, owner: str, fence: int, payload: dict[str, Any],
                    ttl_ms: int = 30_000) -> str:
        if ttl_ms <= 0:
            raise ReceiptError("ttl_ms must be positive")
        encoded = canonical_json(payload)
        digest = sha256(encoded).hex()
        now = time.time_ns()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            lease = db.execute("SELECT * FROM leases WHERE run_id=?", (run_id,)).fetchone()
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if (not lease or not run or lease["owner"] != owner or run["owner"] != owner
                or lease["fence"] != fence or run["fence"] != fence
                or lease["expires_ns"] <= now or run["closed"]):
                db.rollback()
                raise ReceiptError("Stale, expired, mismatched or closed run lease")
            seq = db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM steps WHERE run_id=?",
                             (run_id,)).fetchone()[0]
            db.execute("INSERT INTO steps(run_id,sequence,payload,step_hash) VALUES(?,?,?,?)",
                       (run_id, seq, encoded, digest))
            db.execute("UPDATE leases SET expires_ns=? WHERE run_id=? AND fence=?",
                       (now + ttl_ms * 1_000_000, run_id, fence))
            db.commit()
        return digest

    def attestation_binding(self, run_id: str, owner: str, fence: int) -> dict[str, Any]:
        """Return the stable binding to sign after all steps and before close_run."""
        with self._connect() as db:
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            lease = db.execute("SELECT * FROM leases WHERE run_id=?", (run_id,)).fetchone()
            steps = db.execute("SELECT sequence,payload,step_hash FROM steps "
                               "WHERE run_id=? ORDER BY sequence", (run_id,)).fetchall()
        if (not run or not lease or run["owner"] != owner or lease["owner"] != owner
            or run["fence"] != fence or lease["fence"] != fence
            or lease["expires_ns"] <= time.time_ns() or run["closed"] or not steps):
            raise ReceiptError("Cannot bind attestation to an invalid, expired or empty run")
        material = [{"sequence": s["sequence"], "payload": json.loads(s["payload"]),
                     "step_hash": s["step_hash"]} for s in steps]
        return {"run_id": run_id, "owner": owner, "fencing_token": fence,
                "started_ns": run["started_ns"],
                "steps_digest": sha256(canonical_json(material)).hex()}

    def close_run(self, run_id: str, owner: str, fence: int,
                  attestation: dict[str, Any] | None = None) -> dict[str, Any]:
        now = time.time_ns()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            lease = db.execute("SELECT * FROM leases WHERE run_id=?", (run_id,)).fetchone()
            run = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            steps = db.execute("SELECT sequence,payload,step_hash FROM steps "
                               "WHERE run_id=? ORDER BY sequence", (run_id,)).fetchall()
            if (not lease or not run or lease["owner"] != owner or run["owner"] != owner
                or lease["fence"] != fence or run["fence"] != fence
                or lease["expires_ns"] <= now or run["closed"]):
                db.rollback()
                raise ReceiptError("Cannot close with stale, expired or already-closed lease")
            if not steps:
                db.rollback()
                raise ReceiptError("Zero-step runs cannot produce a receipt")
            if [s["sequence"] for s in steps] != list(range(1, len(steps) + 1)):
                db.rollback()
                raise ReceiptError("Step sequence is not contiguous")
            step_material = [{"sequence": s["sequence"], "payload": json.loads(s["payload"]),
                              "step_hash": s["step_hash"]} for s in steps]
            steps_digest = sha256(canonical_json(step_material)).hex()
            expected_binding = {"run_id": run_id, "owner": owner, "fencing_token": fence,
                                "started_ns": run["started_ns"], "steps_digest": steps_digest}
            if not isinstance(attestation, dict) or attestation.get("binding") != expected_binding:
                db.rollback()
                raise ReceiptError("Attestation must carry the exact stable run binding")
            receipt = {
                "schema": "receiptchain.receipt.v3", "run_id": run_id,
                "owner": owner, "fencing_token": fence,
                "started_ns": run["started_ns"], "closed_ns": now,
                "step_count": len(steps), "steps_digest": steps_digest,
                "steps": step_material,
                "attestation": attestation,
            }
            encoded = canonical_json(receipt)
            receipt_hash = sha256(encoded).hex()
            db.execute("INSERT INTO log_leaves(leaf) VALUES(?)", (encoded,))
            leaf_index = db.execute("SELECT last_insert_rowid()").fetchone()[0] - 1
            db.execute("INSERT INTO receipts(run_id,fence,receipt,receipt_hash,leaf_index) "
                       "VALUES(?,?,?,?,?)", (run_id, fence, encoded, receipt_hash, leaf_index))
            db.execute("UPDATE runs SET closed=1 WHERE run_id=? AND fence=?",
                       (run_id, fence))
            db.execute("DELETE FROM leases WHERE run_id=? AND fence=?", (run_id, fence))
            db.commit()
        return {"receipt": receipt, "receipt_hash": receipt_hash, "leaf_index": leaf_index}

    def proof_bundle(self, run_id: str, checkpoint: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as db:
            receipt_row = db.execute("SELECT * FROM receipts WHERE run_id=?", (run_id,)).fetchone()
            leaves = [r["leaf"] for r in db.execute("SELECT leaf FROM log_leaves ORDER BY leaf_index")]
        if not receipt_row:
            raise ReceiptError("No committed receipt for run")
        idx = receipt_row["leaf_index"]
        root = merkle_root(leaves)
        return {"schema": "receiptchain.bundle.v3", "receipt": json.loads(receipt_row["receipt"]),
                "receipt_hash": receipt_row["receipt_hash"], "leaf_index": idx,
                "tree_size": len(leaves), "root_hash": root.hex(),
                "inclusion_proof": [p.hex() for p in inclusion_proof(leaves, idx)],
                "checkpoint": checkpoint}


def verify_bundle(bundle: dict[str, Any], policy: AttestationPolicy,
                  checkpoint_verifier: Callable[[dict[str, Any]], bool]) -> bool:
    """Offline verification; no database or network access is performed."""
    try:
        if bundle.get("schema") != "receiptchain.bundle.v3":
            return False
        receipt = bundle["receipt"]
        if receipt.get("schema") != "receiptchain.receipt.v3" or receipt.get("step_count", 0) < 1:
            return False
        if receipt["step_count"] != len(receipt["steps"]):
            return False
        if [s["sequence"] for s in receipt["steps"]] != list(range(1, len(receipt["steps"]) + 1)):
            return False
        for step in receipt["steps"]:
            if sha256(canonical_json(step["payload"])).hex() != step["step_hash"]:
                return False
        encoded = canonical_json(receipt)
        if sha256(encoded).hex() != bundle["receipt_hash"]:
            return False
        index, size = bundle["leaf_index"], bundle["tree_size"]
        proof = [bytes.fromhex(p) for p in bundle["inclusion_proof"]]
        root = bytes.fromhex(bundle["root_hash"])
        if not verify_inclusion(encoded, index, size, proof, root):
            return False
        checkpoint = bundle["checkpoint"]
        if (checkpoint.get("tree_size") != size or checkpoint.get("root_hash") != root.hex()
            or not checkpoint_verifier(checkpoint)):
            return False
        attestation = receipt.get("attestation")
        if not isinstance(attestation, dict):
            return False
        step_material = receipt["steps"]
        expected_steps_digest = sha256(canonical_json(step_material)).hex()
        if receipt.get("steps_digest") != expected_steps_digest:
            return False
        binding = {"run_id": receipt["run_id"], "owner": receipt["owner"],
                   "fencing_token": receipt["fencing_token"],
                   "started_ns": receipt["started_ns"],
                   "steps_digest": expected_steps_digest}
        if attestation.get("binding") != binding:
            return False
        verify_attestation(binding, attestation, policy)
        return True
    except (KeyError, TypeError, ValueError, ReceiptError, UnicodeError):
        return False
