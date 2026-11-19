from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from receiptchain_v3 import (
    AttestationPolicy, ReceiptChain, ReceiptError, canonical_json,
    consistency_proof, inclusion_proof, merkle_root, verify_bundle, verify_consistency, verify_inclusion,
)


class ReceiptChainV3Tests(unittest.TestCase):
    def test_canonical_json_orders_keys_by_utf16_and_rejects_unsafe_numbers(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), b'{"a":2,"b":1}')
        with self.assertRaises(ReceiptError):
            canonical_json({"unsafe": 2**53})
        with self.assertRaises(ReceiptError):
            canonical_json({"float": 1.25})

    def test_rfc6962_inclusion_proofs_bind_every_index_and_tree_size(self):
        for size in range(1, 20):
            leaves = [f"leaf-{i}".encode() for i in range(size)]
            root = merkle_root(leaves)
            for index, leaf in enumerate(leaves):
                proof = inclusion_proof(leaves, index)
                self.assertTrue(verify_inclusion(leaf, index, size, proof, root))
                self.assertFalse(verify_inclusion(leaf, size, size, proof, root))
            self.assertFalse(verify_inclusion(leaves[0], 0, size + 1, inclusion_proof(leaves, 0), root))

    def test_rfc6962_consistency_proofs_bind_old_and_new_tree_roots(self):
        for new_size in range(2, 24):
            leaves = [f"leaf-{i}".encode() for i in range(new_size)]
            new_root = merkle_root(leaves)
            for old_size in range(1, new_size):
                proof = consistency_proof(leaves, old_size)
                self.assertTrue(verify_consistency(
                    old_size, new_size, merkle_root(leaves[:old_size]), new_root, proof
                ))
                self.assertFalse(verify_consistency(
                    old_size, new_size, merkle_root(leaves[:old_size]),
                    hashlib.sha256(b"forged-root").digest(), proof
                ))

    def test_zero_step_run_cannot_be_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            chain = ReceiptChain(Path(tmp) / "ledger.sqlite")
            fence = chain.begin_run("r0", "worker-a")
            with self.assertRaisesRegex(ReceiptError, "Zero-step"):
                chain.close_run("r0", "worker-a", fence)

    def test_fencing_rejects_stale_worker_after_lease_reacquisition(self):
        with tempfile.TemporaryDirectory() as tmp:
            chain = ReceiptChain(Path(tmp) / "ledger.sqlite")
            old = chain.begin_run("race", "worker-a", ttl_ms=1)
            with chain._connect() as db:
                db.execute("UPDATE leases SET expires_ns=0 WHERE run_id='race'")
            new = chain.begin_run("race", "worker-b")
            self.assertGreater(new, old)
            with self.assertRaisesRegex(ReceiptError, "Stale"):
                chain.record_step("race", "worker-a", old, {"action": "stale"})
            chain.record_step("race", "worker-b", new, {"action": "valid"})

    def test_offline_bundle_rejects_forged_receipt_and_accepts_valid_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            chain = ReceiptChain(Path(tmp) / "ledger.sqlite")
            fence = chain.begin_run("run-1", "runner-1")
            chain.record_step("run-1", "runner-1", fence, {"command": "unit-test", "exit_code": 0})
            binding = chain.attestation_binding("run-1", "runner-1", fence)
            report_data = hashlib.sha512(
                b"ReceiptChain/TDX/report-data/v3\x00" + canonical_json(binding)
            ).digest()
            evidence = {"quote": "base64-encoded-quote", "collateral": {"pck_chain": "fixture"}}
            attestation = {**evidence, "binding": binding, "fixture_report_data": report_data.hex()}
            committed = chain.close_run("run-1", "runner-1", fence, attestation)
            with chain._connect() as db:
                rows = [r["leaf"] for r in db.execute("SELECT leaf FROM log_leaves ORDER BY leaf_index")]
            root = merkle_root(rows).hex()
            checkpoint = {"origin": "test-log", "tree_size": len(rows), "root_hash": root,
                          "signatures": [{"key_id": "test-witness", "sig": "fixture"}]}

            def quote_verifier(ev):
                return {"verified": True, "report_data": bytes.fromhex(ev["fixture_report_data"]),
                        "mrtd": "allowlisted-mrtd", "tcb_status": "up-to-date"}

            policy = AttestationPolicy(
                allowed_mrtd=frozenset({"allowlisted-mrtd"}),
                quote_verifier=quote_verifier,
                tcb_policy=lambda q: q.get("tcb_status") == "up-to-date",
            )
            bundle = chain.proof_bundle("run-1", checkpoint)
            self.assertTrue(verify_bundle(bundle, policy, lambda cp: len(cp["signatures"]) == 1))
            forged = {**bundle, "receipt": {**bundle["receipt"], "owner": "attacker"}}
            self.assertFalse(verify_bundle(forged, policy, lambda cp: True))
            bad_checkpoint = {**bundle, "checkpoint": {**checkpoint, "root_hash": "00" * 32}}
            self.assertFalse(verify_bundle(bad_checkpoint, policy, lambda cp: True))
            self.assertEqual(committed["receipt_hash"], bundle["receipt_hash"])

    def test_attestation_measurement_and_tcb_policy_fail_closed(self):
        binding = {"run_id": "r", "owner": "o", "fencing_token": 1,
                   "started_ns": 1, "steps_digest": "ab"}
        report_data = hashlib.sha512(
            b"ReceiptChain/TDX/report-data/v3\x00" + canonical_json(binding)
        ).digest()
        evidence = {"quote": "q", "collateral": "c"}
        quote = {"verified": True, "report_data": report_data, "mrtd": "bad", "tcb_status": "revoked"}
        policy = AttestationPolicy(frozenset({"good"}), lambda _: quote,
                                   lambda q: q["tcb_status"] == "up-to-date")
        with tempfile.TemporaryDirectory() as tmp:
            chain = ReceiptChain(Path(tmp) / "ledger.sqlite")
            fence = chain.begin_run("unused", "worker")
            with self.assertRaises(ReceiptError):
                from receiptchain_v3 import verify_attestation
                verify_attestation(binding, evidence, policy)


if __name__ == "__main__":
    unittest.main()
