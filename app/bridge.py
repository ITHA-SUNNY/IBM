"""Threshold — console bridge (M5).

Ties the three shared contracts to the Streamlit console:

    events.csv   -> replay stream            (M2)
    evidence.json-> evidence panel           (M3)
    audit.jsonl  -> decision + chain panel   (M4)

Two modes:

    Stub  - reads the fixtures in app/stubs/ (works today, no other member)
    Live  - prefers data/demo_stream.csv, predict.py (M3, repo root or model/),
            policy/engine.py, and audit/audit.jsonl; silently falls back to
            stubs for anything that is not there yet, and reports what it found.

The policy mirror in app.contracts is used only in Stub mode. Live mode always
uses policy/engine.py when it is present.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.contracts import (
    EVENTS_COLUMNS,
    POLICY_VERSION_FALLBACK,
    ZERO_HASH,
    compute_entry_hash,
    entry_hash_candidates,
    preview_decision,
)

APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
STUB_DIR = APP_DIR / "stubs"

STUB_EVENTS = STUB_DIR / "demo_stream.csv"
STUB_EVIDENCE = STUB_DIR / "evidence.json"
STUB_AUDIT = STUB_DIR / "audit.jsonl"

WORK_AUDIT = STUB_DIR / "_working_audit.jsonl"

# Live-mode candidates (first match wins).
# These mirror the team repo layout: data/ (M2), model/ or root predict.py (M3),
# policy/ (M4), audit/ (M4).
LIVE_EVENTS_CANDIDATES = [
    REPO_ROOT / "data" / "demo_stream.csv",
    REPO_ROOT / "data" / "events.csv",
    REPO_ROOT / "demo_stream.csv",
]
LIVE_EVIDENCE_CANDIDATES = [
    REPO_ROOT / "data" / "evidence.json",
    REPO_ROOT / "evidence.json",
]
LIVE_AUDIT_CANDIDATES = [
    REPO_ROOT / "audit" / "audit.jsonl",
    REPO_ROOT / "data" / "audit.jsonl",
    REPO_ROOT / "audit.jsonl",
]
# M3 stub lives at the repo root as predict.py; model/predict.py is the planned
# final location. Both are probed.
PREDICT_CANDIDATES = [
    REPO_ROOT / "model" / "predict.py",
    REPO_ROOT / "predict.py",
    REPO_ROOT / "threshold" / "models" / "predict.py",
    REPO_ROOT / "models" / "predict.py",
]
ENGINE_CANDIDATES = [
    REPO_ROOT / "policy" / "engine.py",
    REPO_ROOT / "policy" / "policy_engine.py",
    REPO_ROOT / "threshold" / "policy" / "engine.py",
]
VERIFY_CANDIDATES = [
    REPO_ROOT / "audit" / "verify.py",
    REPO_ROOT / "audit" / "verify_audit.py",
    REPO_ROOT / "threshold" / "audit" / "verify.py",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "t"}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pick(obj: Any, names: list[str]) -> Callable | None:
    for n in names:
        fn = getattr(obj, n, None)
        if callable(fn):
            return fn
    return None


# ---------------------------------------------------------------------------
# Evidence keyframes (Stub mode)
# ---------------------------------------------------------------------------


@dataclass
class Session:
    session_id: str
    actor: str
    scenario_id: str
    system_id: str
    kind: str  # "attack" | "lookalike"
    events: list[dict[str, Any]] = field(default_factory=list)
    keyframes: dict[str, dict[str, Any]] = field(default_factory=dict)

    def event_ids(self) -> list[str]:
        return [e["event_id"] for e in self.events]

    def evidence_for(self, event_id: str) -> dict[str, Any] | None:
        return self.keyframes.get(event_id)

    def evidence_upto(self, local_index: int) -> dict[str, Any] | None:
        """Latest keyframe at or before events[local_index]."""
        for e in reversed(self.events[: local_index + 1]):
            kf = self.keyframes.get(e["event_id"])
            if kf:
                return kf
        return None

    def seen_evidence(self, upto: int) -> list[dict[str, Any]]:
        """Keyframes for events[0..upto] in order (may be empty)."""
        out = []
        for e in self.events[: upto + 1]:
            kf = self.keyframes.get(e["event_id"])
            if kf:
                out.append(kf)
        return out


@dataclass
class ConsoleData:
    mode: str
    events: list[dict[str, Any]]
    sessions: dict[str, Session]
    evidence: list[dict[str, Any]]
    audit: list[dict[str, Any]]
    audit_store: "AuditStore"
    sources: dict[str, str]
    live: "LivePipeline | None" = None


# ---------------------------------------------------------------------------
# Audit store: append-only work file, tamper copy, verification
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    ok: bool
    broken_seq: int | None = None
    line_no: int | None = None
    expected: str | None = None
    actual: str | None = None
    verifier: str = "app.bridge (fallback)"
    message: str = ""


class AuditStore:
    def __init__(self, seed_path: Path, work_path: Path = WORK_AUDIT):
        self.seed_path = seed_path
        self.work_path = work_path
        self.reset()

    def reset(self) -> None:
        if self.seed_path.exists():
            shutil.copyfile(self.seed_path, self.work_path)
        else:
            self.work_path.write_text("", encoding="utf-8")

    def entries(self) -> list[dict[str, Any]]:
        return read_audit(self.work_path)

    def append(self, fields: dict[str, Any]) -> dict[str, Any]:
        entries = self.entries()
        prev = entries[-1]["entry_hash"] if entries else ZERO_HASH
        entry = {
            "seq": (entries[-1]["seq"] + 1) if entries else 1,
            "prev_hash": prev,
            **fields,
        }
        entry["entry_hash"] = compute_entry_hash(prev, entry)
        with self.work_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def tamper(self, seq: int, field: str, value: Any) -> int:
        """Edit one line of the working log in place; return the 1-based line no.

        Deliberately edits the live working file (not a copy) so the chain stays
        visibly broken until Reset — that is the demo. Reset restores the seed.
        """
        entries = self.entries()
        line_no = 0
        for i, e in enumerate(entries):
            if e.get("seq") == seq:
                e[field] = value
                line_no = i + 1
                break
        with self.work_path.open("w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, sort_keys=True) + "\n")
        return line_no

    def verify(self, path: Path | None = None) -> VerifyResult:
        target = path or self.work_path
        entries = read_audit(target)

        # Prefer M4's verifier if it is present.
        real = self._try_real_verifier(target)
        if real is not None:
            return real

        prev = ZERO_HASH
        for i, e in enumerate(entries):
            candidates = entry_hash_candidates(prev, e)
            actual = e.get("entry_hash")
            if e.get("prev_hash") != prev or actual not in candidates:
                return VerifyResult(
                    ok=False,
                    broken_seq=e.get("seq"),
                    line_no=i + 1,
                    expected=candidates[0],
                    actual=str(actual),
                    message=f"Entry #{e.get('seq')} (line {i + 1}) does not match "
                            "the chain.",
                )
            prev = actual
        return VerifyResult(ok=True, message="Chain intact.")

    def _try_real_verifier(self, target: Path) -> VerifyResult | None:
        verify_path = next((p for p in VERIFY_CANDIDATES if p.exists()), None)
        if verify_path is None:
            return None
        try:
            module = _load_module(verify_path, "threshold_verify")
            fn = _pick(module, ["verify_log", "verify_file", "verify", "run"])
            if fn is None:
                return None
            result = fn(str(target))
            return _coerce_verify(result, source=f"{verify_path.name} (M4)")
        except Exception:  # noqa: BLE001 - never let the verifier UI crash
            return None


def _coerce_verify(result: Any, source: str) -> VerifyResult | None:
    if isinstance(result, VerifyResult):
        result.verifier = source
        return result
    if isinstance(result, bool):
        return VerifyResult(ok=result, verifier=source)
    if isinstance(result, dict):
        return VerifyResult(
            ok=bool(result.get("ok", result.get("valid", False))),
            broken_seq=result.get("broken_seq") or result.get("seq"),
            line_no=result.get("line_no") or result.get("line"),
            expected=result.get("expected"),
            actual=result.get("actual"),
            verifier=source,
            message=str(result.get("message", "")),
        )
    return None


def read_audit(path: Path) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# Live pipeline resolution
# ---------------------------------------------------------------------------


class LivePipeline:
    def __init__(self) -> None:
        self.predict: Callable | None = None
        self.predict_stream: Callable | None = None
        self.predict_path: Path | None = None
        self.decide: Callable | None = None
        self.notes: list[str] = []
        self.tail_log: list[str] = []

    def status(self) -> list[tuple[str, str]]:
        """(component, one-line status)."""
        def line(name: str, obj: Any) -> tuple[str, str]:
            return (name, "connected" if obj else "not found — using stub")

        return [
            line("predict.py (M3)", self.predict or self.predict_stream),
            line("engine.py (M4)", self.decide),
        ]


def resolve_live() -> LivePipeline:
    live = LivePipeline()
    for path in PREDICT_CANDIDATES:
        if path.exists():
            try:
                module = _load_module(path, "threshold_predict")
                stream = getattr(module, "predict_stream", None)
                sess = _pick(module, ["predict_session", "predict", "run", "infer"])
                if callable(stream):
                    live.predict_stream = stream
                if sess:
                    live.predict = sess
                if live.predict or live.predict_stream:
                    live.predict_path = path
                    live.notes.append(f"predict: {path}")
                    break
            except Exception as exc:  # noqa: BLE001
                live.notes.append(f"predict import failed: {exc!r}")
    for path in ENGINE_CANDIDATES:
        if path.exists():
            try:
                module = _load_module(path, "threshold_engine")
                fn = _pick(module, ["decide", "evaluate", "apply", "run"])
                if fn:
                    live.decide = fn
                    live.notes.append(f"engine: {path}")
                    break
            except Exception as exc:  # noqa: BLE001
                live.notes.append(f"engine import failed: {exc!r}")
    return live


def _call_flexible(fn: Callable, events: list[dict], session_id: str):
    """Try common M3/M4 signatures; return None on any failure."""
    attempts = (
        lambda: fn(events),
        lambda: fn(events=events),
        lambda: fn(list(events)),
        lambda: fn(session_id=session_id, events=events),
        lambda: fn(session_id, events),
    )
    for attempt in attempts:
        try:
            return attempt()
        except TypeError:
            continue
        except Exception:  # noqa: BLE001
            return None
    return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_events(path: Path) -> list[dict[str, Any]]:
    with Path(path).open("r", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    events = []
    for row in rows:
        e = {k: row.get(k, "") for k in EVENTS_COLUMNS}
        e["off_hours"] = _bool(row.get("off_hours"))
        events.append(e)
    # keep contract order but sort by timestamp then event_id for the stream
    events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return events


def load_stub_evidence() -> list[dict[str, Any]]:
    if not STUB_EVIDENCE.exists():
        return []
    return json.loads(STUB_EVIDENCE.read_text(encoding="utf-8"))


def load_evidence_file(path: Path) -> list[dict[str, Any]]:
    """Accept a JSON list of evidence objects or a single evidence object."""
    if not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        # A single evidence object, or a wrapper like {"evidence": [...]}.
        for key in ("evidence", "items", "records", "list"):
            if isinstance(raw.get(key), list):
                return raw[key]
        return [raw]
    if isinstance(raw, list):
        return raw
    return []


def _scenario_kind(scenario_id: str) -> str:
    s = (scenario_id or "").upper()
    return "lookalike" if ("LOOK" in s or "LK" in s) else "attack"


def build_sessions(events: list[dict[str, Any]],
                   evidence: list[dict[str, Any]]) -> dict[str, Session]:
    by_session_key: dict[str, Session] = {}
    for e in events:
        sid = e["session_id"]
        sess = by_session_key.get(sid)
        if sess is None:
            sess = Session(
                session_id=sid,
                actor=e["actor_id"],
                scenario_id=e["scenario_id"],
                system_id=e["system_id"],
                kind=_scenario_kind(e["scenario_id"]),
                events=[],
            )
            by_session_key[sid] = sess
        sess.events.append(e)

    # Map each evidence object onto a session event.
    #  1) explicit after_event_id (M5 fixtures / M3 stream), else
    #  2) the latest event listed in top_events for that session, else
    #  3) the last event of the session (repo stub evidence.json).
    for ev in evidence:
        after = ev.get("after_event_id")
        if after:
            sid = ev.get("session_id") or _session_of_event(by_session_key, after)
            if sid in by_session_key and any(
                e["event_id"] == after for e in by_session_key[sid].events
            ):
                by_session_key[sid].keyframes[after] = ev
            continue

        sid = ev.get("session_id")
        sess = by_session_key.get(sid)
        if sess is None:
            continue
        target = None
        tops = [t for t in (ev.get("top_events") or []) if isinstance(t, str)]
        for t in reversed(tops):
            if any(e["event_id"] == t for e in sess.events):
                target = t
                break
        if target is None and sess.events:
            target = sess.events[-1]["event_id"]
        if target:
            sess.keyframes[target] = ev
    return by_session_key


def _session_of_event(sessions: dict[str, Session], event_id: str) -> str | None:
    for sid, sess in sessions.items():
        if any(e["event_id"] == event_id for e in sess.events):
            return sid
    return None


def _rel(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def load_console_data(mode: str = "stub") -> ConsoleData:
    live = None
    sources: dict[str, str] = {}

    events_path = STUB_EVENTS
    if mode == "live":
        found = next((p for p in LIVE_EVENTS_CANDIDATES if p.exists()), None)
        if found:
            events_path = found
    sources["events"] = _rel(events_path)
    events = load_events(events_path)

    if mode == "live":
        live = resolve_live()

    # Evidence: the shared contract says M3 *publishes* evidence.json and M5
    # reads it. So Live mode prefers data/evidence.json / stub_evidence.json,
    # and only falls back to calling predict_stream when no such file exists.
    evidence_path = STUB_EVIDENCE
    found_ev = None
    if mode == "live":
        found_ev = next((p for p in LIVE_EVIDENCE_CANDIDATES if p.exists()), None)

    if found_ev:
        evidence_path = found_ev
        evidence = load_evidence_file(found_ev)
    elif mode == "live" and live and live.predict_stream:
        evidence_path = live.predict_path or STUB_EVIDENCE
        evidence = []
    else:
        evidence = load_stub_evidence()
    sources["evidence"] = _rel(evidence_path)

    seed = STUB_AUDIT
    if mode == "live":
        found_audit = next((p for p in LIVE_AUDIT_CANDIDATES if p.exists()), None)
        if found_audit:
            seed = found_audit
    sources["audit"] = _rel(seed)
    audit_store = AuditStore(seed)

    sessions = build_sessions(events, evidence)

    # If no published evidence.json exists, derive one keyframe per event from
    # M3's predict_stream (prefix-based), aligned to each session's events.
    if mode == "live" and live and live.predict_stream and not found_ev:
        n = _apply_live_stream(live.predict_stream, sessions)
        if n:
            sources["evidence"] = f"{_rel(live.predict_path)} · {n} keyframes (M3)"

    return ConsoleData(
        mode=mode,
        events=events,
        sessions=sessions,
        evidence=evidence,
        audit=audit_store.entries(),
        audit_store=audit_store,
        sources=sources,
        live=live,
    )


def _apply_live_stream(fn: Callable, sessions: dict[str, Session]) -> int:
    """Attach per-event evidence from M3 predict_stream; return keyframe count."""
    added = 0
    for sess in sessions.values():
        result = _call_flexible(fn, sess.events, sess.session_id)
        if not isinstance(result, list) or len(result) != len(sess.events):
            continue
        for ev, event in zip(result, sess.events):
            if isinstance(ev, dict) and ev.get("current_stage"):
                sess.keyframes[event["event_id"]] = ev
                added += 1
    return added


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def decide(data: ConsoleData, evidence: dict[str, Any]) -> dict[str, str]:
    """Live engine when present, otherwise the stub policy mirror."""
    if data.live and data.live.decide:
        result = _call_flexible(
            data.live.decide, [evidence], evidence.get("session_id", "")
        )
        coerced = _coerce_decision(result)
        if coerced:
            coerced.setdefault("source", "policy/engine.py (M4)")
            return coerced
    out = preview_decision(evidence)
    out["source"] = "stub policy mirror (M5)"
    return out


def _coerce_decision(result: Any) -> dict[str, str] | None:
    if isinstance(result, dict):
        action = result.get("action") or result.get("decision")
        if not action:
            return None
        return {
            "action": str(action),
            "rule_fired": str(result.get("rule_fired", result.get("rule", ""))),
            "reason": str(result.get("reason", "")),
        }
    if isinstance(result, str):
        return {"action": result, "rule_fired": "", "reason": ""}
    return None


def predict_evidence(live: LivePipeline | None, session: Session,
                     events: list[dict[str, Any]]):
    """Live model evidence for the events seen so far, else None."""
    if not live or not live.predict:
        return None
    result = _call_flexible(live.predict, events, session.session_id)
    if isinstance(result, dict) and result.get("current_stage"):
        return result
    return None


# ---------------------------------------------------------------------------
# Playlist and view computation helpers
# ---------------------------------------------------------------------------


def pick_sessions(data: ConsoleData, scenario: str) -> list[Session]:
    attack = next((s for s in data.sessions.values() if s.kind == "attack"), None)
    look = next((s for s in data.sessions.values() if s.kind == "lookalike"), None)
    if scenario == "attack":
        return [s for s in (attack,) if s]
    if scenario == "lookalike":
        return [s for s in (look,) if s]
    return [s for s in (attack, look) if s]


def make_playlist(data: ConsoleData, scenario: str) -> list[tuple[Session, dict]]:
    playlist: list[tuple[Session, dict]] = []
    for s in pick_sessions(data, scenario):
        playlist += [(s, e) for e in s.events]
    return playlist


def local_index(session: Session, event: dict) -> int:
    return session.event_ids().index(event["event_id"])


def policy_version(data: ConsoleData) -> str:
    entries = data.audit_store.entries()
    return entries[-1]["policy_version"] if entries else POLICY_VERSION_FALLBACK


def compute_view(data: ConsoleData, playlist: list[tuple[Session, dict]], step: int):
    session, event = playlist[step]
    li = local_index(session, event)
    evidence = session.evidence_upto(li)
    if evidence is None and data.live and data.live.predict:
        evidence = predict_evidence(data.live, session, session.events[: li + 1])
    if evidence:
        decision = decide(data, evidence)
    else:
        decision = {
            "action": "LOG_ONLY",
            "rule_fired": "—",
            "reason": "No evidence object yet for this position.",
            "source": "—",
        }
    revealed: set[str] = set()
    for i in range(step + 1):
        s, e = playlist[i]
        kf = s.evidence_for(e["event_id"])
        if kf:
            revealed.add(kf["evidence_id"])
    return session, event, li, evidence, decision, revealed

