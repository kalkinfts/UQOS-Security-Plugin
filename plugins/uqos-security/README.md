# UQOS Security Plugin

Standalone Claude Code plugin for authorized defensive assessment.

The runner validates tool and target policy, selects a backend, applies a hard timeout, captures results, emits JSON evidence, hashes the result, and appends a chained audit record.

Example:

python scripts/uqos_run.py --tool nmap --target localhost

For active execution:

python scripts/uqos_run.py --tool nmap --target 127.0.0.1 --execute

Public active targets require UQOS_AUTH_TOKEN. Keep testing inside systems for which you have explicit permission.
