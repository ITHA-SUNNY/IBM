"""Audit log verifier (M4) for any audit.jsonl in the shared contract.

    python audit/verify.py audit/audit.jsonl        # exit code 1 if tampered

The M5 console finds this file and calls verify_log(path); it uses the same
hash chain as policy/policy_agent/audit.py:

    entry_hash = SHA-256(prev_hash + canonical_json(entry without entry_hash))
"""
from __future__ import annotations

import sys
from pathlib import Path

_POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"
if str(_POLICY_DIR) not in sys.path:
    sys.path.insert(0, str(_POLICY_DIR))

from policy_agent.audit import AuditLog  # noqa: E402


def verify_log(path: str) -> dict:
    """{ok, entries, broken_seq, line_no, message, head_hash} for the log at path."""
    result = AuditLog(path).verify()
    return {
        "ok": result.ok,
        "entries": result.entries,
        "broken_seq": result.broken_seq,
        "line_no": result.line_no,
        "message": "Chain intact." if result.ok else result.problem,
        "head_hash": result.head_hash,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python audit/verify.py <audit.jsonl>", file=sys.stderr)
        raise SystemExit(2)
    out = verify_log(sys.argv[1])
    if out["ok"]:
        print(f"OK: {out['entries']} entries, head hash {out['head_hash']}")
        raise SystemExit(0)
    print(f"TAMPERING OR CORRUPTION DETECTED after {out['entries']} good entries: {out['message']}")
    raise SystemExit(1)
