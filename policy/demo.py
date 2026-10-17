"""Demo of the policy side, runnable on its own:  python3 demo.py

Reads examples/evidence_feed.jsonl (what the model side will eventually send),
prints each decision, shows WHY one case did not revoke, replays one actor from
the audit log, then proves the log is tamper-evident.

Writes to demo_output/:
    audit_log.jsonl        the hash-chained audit log
    demo_decisions.jsonl   one decision per line, ready for a dashboard to read
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from policy_agent import AuditLog, PolicyAgent

HERE = Path(__file__).resolve().parent
OUT = HERE / "demo_output"
FEED = HERE / "examples" / "evidence_feed.jsonl"


def banner(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    audit_path = OUT / "audit_log.jsonl"
    agent = PolicyAgent(audit_path=str(audit_path))

    feed = [json.loads(line) for line in FEED.read_text(encoding="utf-8").splitlines() if line.strip()]

    banner("1. Evidence in, decisions out (severity and confidence are separate columns)")
    print(f"{'actor':<10} {'severity':<9} {'conf':>5} {'ind':>3}  {'decision':<17} {'rule':<8} case")
    print("-" * 78)
    decisions = []
    for item in feed:
        d = agent.process(item)
        decisions.append(d)
        conf = "-" if d.confidence is None else f"{d.confidence:.2f}"
        ind = "-" if d.indicator_count is None else str(d.indicator_count)
        flag = " *" if d.automated else ""
        print(f"{d.target['actor_id']:<10} {d.severity:<9} {conf:>5} {ind:>3}  {d.action + flag:<17} "
              f"{d.rule_id:<8} {item.get('label', '')}")
    print("\n* = automated action (changes system state). Everything else leaves the decision to a human.")

    (OUT / "demo_decisions.jsonl").write_text(
        "\n".join(json.dumps(d.to_dict()) for d in decisions) + "\n", encoding="utf-8"
    )

    banner("2. Why rkapoor was NOT revoked (same CRITICAL severity as jmartinez)")
    rkapoor = next(d for d in decisions if d.target["actor_id"] == "rkapoor")
    for step in rkapoor.trace:
        verdict = "MATCHED " if step["matched"] else "no match"
        print(f"  {step['rule_id']}  {verdict}  {step['action']:<16} {step['name']}")
        for why in step["failed_conditions"]:
            print(f"            - {why}")
    print(f"\n  Decision: {rkapoor.action}. {rkapoor.reason}")

    banner("3. Severity is the policy's call, not the model's (mlopez)")
    mlopez = next(d for d in decisions if d.target["actor_id"] == "mlopez")
    print(f"  Upstream sent severity LOW. Policy computed {mlopez.severity} (score {mlopez.severity_score}).")
    for note in mlopez.notes:
        print(f"  Note: {note}")

    banner("4. Bad input fails safe (bkumar sent confidence 1.7 and no privilege flag)")
    bad = next(d for d in decisions if d.rule_id == "FAILSAFE")
    print(f"  Decision: {bad.action}, automated={bad.automated}")
    print(f"  {bad.reason}")

    banner("5. Audit replay: 'show me why this account was revoked' (jmartinez)")
    entry = AuditLog(str(audit_path)).replay(actor_id="jmartinez")[0]
    print(f"  entry #{entry['seq']} logged {entry['logged_at']}  (policy v{entry['policy_version']})")
    print(f"  evidence hash : {entry['evidence_hash'][:24]}...")
    print(f"  indicators    : {', '.join(entry['evidence']['indicators'])}")
    print(f"  decision      : {entry['decision']['action']} via {entry['decision']['rule_id']} "
          f"({entry['decision']['rule_name']})")
    print(f"  reason        : {entry['decision']['reason']}")

    banner("6. Tamper check")
    result = AuditLog(str(audit_path)).verify()
    print(f"  Original log : ok={result.ok}, {result.entries} entries, head {result.head_hash[:24]}...")
    tampered = OUT / "audit_log_TAMPERED.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[0])
    edited["decision"]["action"] = "LOG_ONLY"  # someone quietly downgrades the revoke
    lines[0] = json.dumps(edited)
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = AuditLog(str(tampered)).verify()
    print(f"  Edited copy  : ok={result.ok} -> {result.problem}")
    tampered.unlink()

    print(f"\nFiles written to {OUT}")


if __name__ == "__main__":
    main()
