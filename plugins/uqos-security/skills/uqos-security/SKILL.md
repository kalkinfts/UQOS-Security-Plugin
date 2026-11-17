---
name: uqos-security
description: Run authorized defensive security checks through the UQOS async bounded runner.
---

# UQOS Security

Use the UQOS runner only for systems the operator owns or is explicitly authorized to assess.

## Workflow

1. Identify the exact target and authorization scope.
2. Run a dry-run first.
3. Use only the six registered adapters: nmap, httpx, nuclei, nikto, amass, subfinder.
4. Use --execute only after scope is confirmed.
5. Consume JSONL execution, stdout/stderr, and result events; preserve the final attestation and audit-chain hash.
6. Report the actual hash algorithm (BLAKE3 if installed, otherwise SHA-256).
7. Do not describe an adapter as supported unless it is present in the allowlist and has tests.

Do not use this skill to gain unauthorized access, evade controls, steal credentials, deploy malware, disrupt services, or attack third-party systems.
