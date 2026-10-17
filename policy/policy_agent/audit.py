"""Append-only, hash-chained audit log (one JSON object per line).

Every entry stores the hash of the entry before it, so editing, deleting or
re-ordering an entry breaks the chain and `verify()` says where. Keep the
latest `head_hash` somewhere outside the file (a screenshot is enough for a
demo): that is what also exposes someone cutting entries off the end.

Single writer assumed: one PolicyAgent per log file.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import AuditError
from .evidence import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    problem: Optional[str]
    head_hash: str


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_line(self) -> Optional[str]:
        if not self.path.exists():
            return None
        with open(self.path, "rb") as handle:
            handle.seek(0, 2)
            pos = handle.tell()
            if pos == 0:
                return None
            data = b""
            while pos > 0 and data.count(b"\n") < 2:
                step = min(4096, pos)
                pos -= step
                handle.seek(pos)
                data = handle.read(step) + data
        lines = [line for line in data.splitlines() if line.strip()]
        return lines[-1].decode("utf-8") if lines else None

    def _tail(self) -> Tuple[str, int]:
        last = self._last_line()
        if last is None:
            return GENESIS_HASH, 0
        try:
            entry = json.loads(last)
            return entry["entry_hash"], int(entry["seq"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AuditError("audit log tail is unreadable; run verify before writing more") from exc

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            prev_hash, seq = self._tail()
            entry = json.loads(canonical_json(record))  # normalise so hashing survives a round trip
            entry["seq"] = seq + 1
            entry["logged_at"] = datetime.now(timezone.utc).isoformat()
            entry["prev_hash"] = prev_hash
            entry["entry_hash"] = sha256_hex(canonical_json(entry))
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(canonical_json(entry) + "\n")
                handle.flush()
            return entry

    def entries(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8") as handle:
            for raw in handle:
                if raw.strip():
                    out.append(json.loads(raw))
        return out

    def head_hash(self) -> str:
        return self._tail()[0]

    def verify(self) -> VerifyResult:
        prev_hash, expected_seq, count = GENESIS_HASH, 1, 0
        if not self.path.exists():
            return VerifyResult(True, 0, None, GENESIS_HASH)
        with open(self.path, "r", encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                try:
                    entry = json.loads(raw)
                    claimed = entry.pop("entry_hash")
                except (ValueError, KeyError, AttributeError):
                    return VerifyResult(False, count, f"line {lineno}: not a valid audit entry", prev_hash)
                if entry.get("seq") != expected_seq:
                    return VerifyResult(
                        False, count,
                        f"line {lineno}: expected seq {expected_seq}, found {entry.get('seq')} (entry missing or reordered)",
                        prev_hash,
                    )
                if entry.get("prev_hash") != prev_hash:
                    return VerifyResult(False, count, f"line {lineno} (seq {expected_seq}): chain link broken", prev_hash)
                if sha256_hex(canonical_json(entry)) != claimed:
                    return VerifyResult(False, count, f"line {lineno} (seq {expected_seq}): content was altered", prev_hash)
                prev_hash, expected_seq, count = claimed, expected_seq + 1, count + 1
        return VerifyResult(True, count, None, prev_hash)

    def replay(self, actor_id: Optional[str] = None, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """All decisions for an actor and/or session, oldest first: 'why did this account get locked?'"""
        matches = []
        for entry in self.entries():
            target = (entry.get("decision") or {}).get("target") or {}
            if actor_id is not None and target.get("actor_id") != actor_id:
                continue
            if session_id is not None and target.get("session_id") != session_id:
                continue
            matches.append(entry)
        return matches
