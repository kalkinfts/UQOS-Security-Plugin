# ReceiptChain v3

ReceiptChain v3 adds a fail-closed execution receipt ledger to UQOS. It is an additive library; the existing six-tool runner remains unchanged.

## Guarantees implemented

- SQLite `BEGIN IMMEDIATE` transactions for lease acquisition and receipt finalization.
- Monotonic per-run fencing tokens; every step and close checks owner, fence, expiry and run lifecycle inside the same write transaction.
- Zero-step runs cannot close or produce a receipt.
- Contiguous step sequence and per-step SHA-256 commitments.
- RFC 6962 domain-separated Merkle leaf/node hashes, inclusion proof generation and verification bound to both leaf index and tree size.
- Offline bundle verification reconstructs the canonical receipt leaf, validates every step hash, checks the inclusion proof and requires an externally verified checkpoint.
- Attestation binding is stable before close: run ID, owner, fencing token, start time and digest of the complete ordered step list.
- SHA-512 report_data binding for the attestation callback.

## Attestation trust boundary

This package does **not** claim to implement Intel's TDX quote parser, Intel QE/PCK certificate validation, CRL/TCB collateral validation, or Sigstore's signed-note format. Those are vendor- and format-specific trust operations and must be supplied by a configured `AttestationPolicy.quote_verifier` and checkpoint-verifier callback.

The quote verifier MUST:
1. Parse the raw signed quote bytes; never trust separately supplied mutable parsed fields.
2. Validate the quote signature and the complete certificate chain to configured Intel trust roots.
3. Validate QE report / attestation-key binding and quote structure according to the supported TDX quote version.
4. Validate collateral freshness, revocation and TCB status.
5. Return `verified=True` only after every required check succeeds, plus the verified report_data and MRTD extracted from the signed quote.

The checkpoint verifier MUST verify the exact checkpoint payload, expected log origin, tree size, root hash, and all required log/witness signer identities. A callback that merely checks that a signature field exists is not sufficient.

The built-in tests use fixture callbacks only to test the receipt protocol. They are **not** evidence of genuine TDX hardware attestation or production PKI verification.

## Canonical JSON profile

Receipt fields use UTF-8 canonical JSON with UTF-16 key ordering and safe integer values. To avoid cross-runtime floating-point serialization ambiguity, this profile rejects floats and integers outside the IEEE-754 safe integer range; encode exact decimal quantities and large counters as strings. This is a constrained RFC 8785-compatible profile, not a claim of complete general-purpose JCS support.

## API sequence

```python
chain = ReceiptChain(".uqos/receiptchain.sqlite")
fence = chain.begin_run("run-123", "runner-a")
chain.record_step("run-123", "runner-a", fence, {"action": "build", "exit_code": 0})

# Obtain the stable binding after all steps; use it to create real quote evidence.
binding = chain.attestation_binding("run-123", "runner-a", fence)
# attestation = create_and_verify_platform_attestation(binding)
result = chain.close_run("run-123", "runner-a", fence, attestation)
# Publish a signed transparency checkpoint, then:
bundle = chain.proof_bundle("run-123", checkpoint)
# Offline:
# verify_bundle(bundle, attestation_policy, checkpoint_verifier)
```

## Tests

Run from repository root:

```bash
python -m unittest discover -s plugins/uqos-security/tests -p "test_receiptchain_v3.py" -v
```

No hardware quote is fabricated by this library. Production enablement requires a real platform verifier and a real signed checkpoint verifier.
