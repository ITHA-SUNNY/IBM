"""Command line access to the policy agent.

    python3 -m policy_agent decide evidence.jsonl --audit audit_log.jsonl
    cat evidence.jsonl | python3 -m policy_agent decide - --audit audit_log.jsonl
    python3 -m policy_agent verify audit_log.jsonl
    python3 -m policy_agent replay audit_log.jsonl --actor jmartinez
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditLog
from .errors import PolicyConfigError
from .pipeline import PolicyAgent


def _read_records(source: str):
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    records = []
    for line in text.splitlines():
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(line)  # goes through validation and comes back as FAILSAFE
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="policy_agent", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    decide = sub.add_parser("decide", help="evaluate evidence objects (JSON array or JSONL) and print decisions")
    decide.add_argument("source", help="file path, or - for stdin")
    decide.add_argument("--audit", default="audit_log.jsonl")
    decide.add_argument("--config", default=None, help="alternate rules.json")

    verify = sub.add_parser("verify", help="check the audit log hash chain")
    verify.add_argument("audit")

    replay = sub.add_parser("replay", help="show logged decisions for an actor or session")
    replay.add_argument("audit")
    replay.add_argument("--actor", default=None)
    replay.add_argument("--session", default=None)

    args = parser.parse_args(argv)

    if args.command == "decide":
        try:
            agent = PolicyAgent(config_path=args.config, audit_path=args.audit)
        except PolicyConfigError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        for record in _read_records(args.source):
            print(json.dumps(agent.process(record).to_dict()))
        return 0

    if args.command == "verify":
        result = AuditLog(args.audit).verify()
        if result.ok:
            print(f"OK: {result.entries} entries, head hash {result.head_hash}")
            return 0
        print(f"TAMPERING OR CORRUPTION DETECTED after {result.entries} good entries: {result.problem}")
        return 1

    if args.command == "replay":
        if args.actor is None and args.session is None:
            print("give --actor and/or --session", file=sys.stderr)
            return 2
        for entry in AuditLog(args.audit).replay(actor_id=args.actor, session_id=args.session):
            print(json.dumps(entry, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
