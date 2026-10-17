"""The deterministic policy engine.

No ML, no randomness, no network, no clock. The same evidence and the same
rules.json always give the same decision. This is the only component that is
allowed to say "revoke" or "lock", and it can only do so when fixed, readable
conditions are met.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import PolicyConfigError
from .evidence import EvidenceObject, canonical_json, normalize_token, sha256_hex
from .severity import SEVERITY_LEVELS, SeverityModel

ACTIONS = ("LOG_ONLY", "EARLY_WARNING", "ALERT_ANALYST", "REVOKE_SESSION", "LOCK_CREDENTIALS")
DESTRUCTIVE_ACTIONS = frozenset({"REVOKE_SESSION", "LOCK_CREDENTIALS"})

# Guardrails enforced when rules.json is loaded. Whoever edits the config cannot
# make the system take a destructive action on thin evidence.
DESTRUCTIVE_MIN_CONFIDENCE_FLOOR = 0.80
DESTRUCTIVE_MIN_INDICATORS_FLOOR = 2
# A destructive rule must exclude this threat type: when the model says the
# activity is benign, its confidence is confidence in "benign", not in a threat.
BENIGN_THREAT_TYPE = "benign"

CONDITION_KEYS = (
    "severity_in",
    "min_confidence",
    "max_confidence_exclusive",
    "min_next_confidence",
    "min_indicators",
    "predicted_next_stage_in",
    "threat_type_not_in",
)
TOKEN_LIST_KEYS = ("predicted_next_stage_in", "threat_type_not_in")

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.json")


@dataclass(frozen=True)
class Decision:
    action: str
    rule_id: str
    rule_name: str
    reason: str
    severity: str
    severity_score: Optional[int]
    confidence: Optional[float]
    indicator_count: Optional[int]
    predicted_next_stage: Optional[str]
    threat_type: Optional[str]
    next_confidence: Optional[float]
    target: Dict[str, Optional[str]]
    automated: bool  # True only for actions that change system state
    policy_version: str
    trace: List[Dict[str, Any]]
    notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_rule(rule: Any, index: int, seen_ids: set) -> List[str]:
    where = f"rules[{index}]"
    if not isinstance(rule, dict):
        return [f"{where} must be an object"]
    problems: List[str] = []

    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        problems.append(f"{where}.id must be a non-empty string")
    elif rule_id in seen_ids:
        problems.append(f"{where}.id '{rule_id}' is duplicated")
    else:
        seen_ids.add(rule_id)
        where = f"rule {rule_id}"

    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        problems.append(f"{where} needs a non-empty name")
    if not isinstance(rule.get("description"), str) or not rule["description"].strip():
        problems.append(f"{where} needs a non-empty description")

    action = rule.get("action")
    if action not in ACTIONS:
        problems.append(f"{where} has unknown action '{action}'")

    when = rule.get("when")
    if not isinstance(when, dict) or not when:
        problems.append(f"{where}.when must be a non-empty object (an empty condition would match everything)")
        return problems

    for key in when:
        if key not in CONDITION_KEYS:
            problems.append(f"{where} has unknown condition '{key}' (allowed: {', '.join(CONDITION_KEYS)})")

    if "severity_in" in when:
        sev = when["severity_in"]
        if not isinstance(sev, list) or not sev or any(s not in SEVERITY_LEVELS for s in sev):
            problems.append(f"{where}.severity_in must be a non-empty list of {', '.join(SEVERITY_LEVELS)}")
    for key in ("min_confidence", "max_confidence_exclusive", "min_next_confidence"):
        if key in when and (not _is_number(when[key]) or not 0.0 <= when[key] <= 1.0):
            problems.append(f"{where}.{key} must be a number between 0 and 1")
    if "min_indicators" in when:
        n = when["min_indicators"]
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            problems.append(f"{where}.min_indicators must be a non-negative integer")
    for key in TOKEN_LIST_KEYS:
        if key in when:
            items = when[key]
            if not isinstance(items, list) or not items or any(not isinstance(s, str) or not s.strip() for s in items):
                problems.append(f"{where}.{key} must be a non-empty list of strings")

    if action in DESTRUCTIVE_ACTIONS:
        if "severity_in" not in when:
            problems.append(f"{where} ({action}) must set severity_in")
        excluded = when.get("threat_type_not_in")
        if not isinstance(excluded, list) or BENIGN_THREAT_TYPE not in [
            normalize_token(s) for s in excluded if isinstance(s, str)
        ]:
            problems.append(f"{where} ({action}) must set threat_type_not_in including '{BENIGN_THREAT_TYPE}'")
        mc = when.get("min_confidence")
        if not _is_number(mc) or mc < DESTRUCTIVE_MIN_CONFIDENCE_FLOOR:
            problems.append(
                f"{where} ({action}) must set min_confidence >= {DESTRUCTIVE_MIN_CONFIDENCE_FLOOR}"
            )
        mi = when.get("min_indicators")
        if not isinstance(mi, int) or isinstance(mi, bool) or mi < DESTRUCTIVE_MIN_INDICATORS_FLOOR:
            problems.append(
                f"{where} ({action}) must set min_indicators >= {DESTRUCTIVE_MIN_INDICATORS_FLOOR}"
            )
    return problems


def _normalise_when(when: Dict[str, Any], aliases: Dict[str, str]) -> Dict[str, Any]:
    out = dict(when)
    for key in TOKEN_LIST_KEYS:
        if key in out:
            out[key] = [_canonical_stage(s, aliases) for s in out[key]]
    return out


def _canonical_stage(value: Optional[str], aliases: Dict[str, str]) -> Optional[str]:
    """'Exfiltration' / 'COLLECTION_EXFIL' -> 'collection_exfil' (via stage_aliases)."""
    if value is None:
        return None
    token = normalize_token(value)
    return aliases.get(token, token)


def _parse_aliases(raw: Any, problems: List[str]) -> Dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) or not k.strip() or not v.strip() for k, v in raw.items()
    ):
        problems.append("stage_aliases must map non-empty strings to non-empty strings")
        return {}
    return {normalize_token(k): normalize_token(v) for k, v in raw.items()}


def _parse_indicators(raw: Any, problems: List[str]) -> Optional[frozenset]:
    """The indicator vocabulary; only these count toward min_indicators. None = count all."""
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw or any(not isinstance(i, str) or not i.strip() for i in raw):
        problems.append("indicators must be a non-empty list of strings")
        return None
    return frozenset(normalize_token(i) for i in raw)


class Policy:
    def __init__(self, config: Dict[str, Any]) -> None:
        if not isinstance(config, dict):
            raise PolicyConfigError("config must be a JSON object")
        problems: List[str] = []

        version = config.get("policy_version")
        if not isinstance(version, str) or not version.strip():
            problems.append("policy_version must be a non-empty string")

        aliases = _parse_aliases(config.get("stage_aliases"), problems)
        indicator_vocab = _parse_indicators(config.get("indicators"), problems)

        rules = config.get("rules")
        validated: List[Dict[str, Any]] = []
        if not isinstance(rules, list) or not rules:
            problems.append("rules must be a non-empty list")
        else:
            seen: set = set()
            for i, rule in enumerate(rules):
                found = _validate_rule(rule, i, seen)
                problems.extend(found)
                if not found:
                    validated.append({**rule, "when": _normalise_when(rule["when"], aliases)})

        default = config.get("default")
        if not isinstance(default, dict) or default.get("action") not in ACTIONS:
            problems.append("default.action must be one of " + ", ".join(ACTIONS))
        elif default["action"] in DESTRUCTIVE_ACTIONS:
            problems.append("default.action may not be a destructive action")
        elif not isinstance(default.get("description"), str) or not default["description"].strip():
            problems.append("default needs a non-empty description")

        try:
            severity_model = SeverityModel(config.get("severity"))
        except PolicyConfigError as exc:
            problems.extend(exc.problems)
            severity_model = None

        if problems:
            raise PolicyConfigError(problems)

        self.version: str = version
        self.rules = validated
        self.default = default
        self.severity_model: SeverityModel = severity_model
        self.stage_aliases: Dict[str, str] = aliases
        self.indicator_vocab: Optional[frozenset] = indicator_vocab
        self.config_hash: str = sha256_hex(canonical_json(config))

    def canonical_stage(self, value: Optional[str]) -> Optional[str]:
        return _canonical_stage(value, self.stage_aliases)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Policy":
        target = Path(path) if path else DEFAULT_RULES_PATH
        try:
            config = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyConfigError(f"cannot read {target}: {exc}") from exc
        return cls(config)

    @staticmethod
    def _failed_conditions(when: Dict[str, Any], facts: Dict[str, Any]) -> List[str]:
        failed: List[str] = []
        if "severity_in" in when and facts["severity"] not in when["severity_in"]:
            failed.append(f"severity {facts['severity']} not in {when['severity_in']}")
        if "min_confidence" in when and facts["confidence"] < when["min_confidence"]:
            failed.append(f"confidence {facts['confidence']:g} < {when['min_confidence']:g} required")
        if "max_confidence_exclusive" in when and facts["confidence"] >= when["max_confidence_exclusive"]:
            failed.append(
                f"confidence {facts['confidence']:g} >= {when['max_confidence_exclusive']:g} (must be below)"
            )
        if "min_next_confidence" in when and facts["next_confidence"] < when["min_next_confidence"]:
            failed.append(
                f"next-stage confidence {facts['next_confidence']:g} < {when['min_next_confidence']:g} required"
            )
        if "min_indicators" in when and facts["indicator_count"] < when["min_indicators"]:
            failed.append(f"indicators {facts['indicator_count']} < {when['min_indicators']} required")
        if "predicted_next_stage_in" in when and facts["predicted_next_stage"] not in when["predicted_next_stage_in"]:
            failed.append(
                f"predicted stage '{facts['predicted_next_stage']}' not in {when['predicted_next_stage_in']}"
            )
        if "threat_type_not_in" in when and facts["threat_type"] in when["threat_type_not_in"]:
            failed.append(f"threat type '{facts['threat_type']}' is excluded {when['threat_type_not_in']}")
        return failed

    def count_indicators(self, indicators: List[str]) -> Tuple[int, List[str]]:
        """(count toward min_indicators, unrecognised indicators that were not counted)."""
        if self.indicator_vocab is None:
            return len(indicators), []
        unknown = [i for i in indicators if normalize_token(i) not in self.indicator_vocab]
        counted = {normalize_token(i) for i in indicators} & self.indicator_vocab
        return len(counted), unknown

    def evaluate(self, ev: EvidenceObject) -> Decision:
        """Raises EvidenceError if the evidence uses a tier or action the policy does not know."""
        severity, score = self.severity_model.compute(ev.resource_tier, ev.action, ev.is_privileged_actor)
        indicator_count, unknown = self.count_indicators(ev.indicators)
        next_confidence = ev.next_confidence if ev.next_confidence is not None else ev.confidence
        facts = {
            "severity": severity,
            "confidence": ev.confidence,
            "next_confidence": next_confidence,
            "indicator_count": indicator_count,
            "predicted_next_stage": self.canonical_stage(ev.predicted_next_stage),
            "threat_type": self.canonical_stage(ev.threat_type),
        }

        notes: List[str] = []
        if "severity" in ev.extras:
            notes.append(
                "Upstream-supplied 'severity' was ignored: severity is computed here from "
                "resource_tier, action and is_privileged_actor."
            )
        if unknown:
            notes.append(
                "Indicators outside the agreed vocabulary were kept but not counted: " + ", ".join(unknown)
            )

        trace: List[Dict[str, Any]] = []
        chosen: Optional[Dict[str, Any]] = None
        for rule in self.rules:
            failed = self._failed_conditions(rule["when"], facts)
            trace.append(
                {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "action": rule["action"],
                    "matched": not failed,
                    "failed_conditions": failed,
                }
            )
            if not failed:
                chosen = rule
                break

        if chosen is not None:
            action, rule_id, rule_name, reason = (
                chosen["action"], chosen["id"], chosen["name"], chosen["description"],
            )
        else:
            action = self.default["action"]
            rule_id, rule_name, reason = "DEFAULT", "No rule matched", self.default["description"]

        return Decision(
            action=action,
            rule_id=rule_id,
            rule_name=rule_name,
            reason=reason,
            severity=severity,
            severity_score=score,
            confidence=ev.confidence,
            indicator_count=indicator_count,
            predicted_next_stage=facts["predicted_next_stage"],
            threat_type=facts["threat_type"],
            next_confidence=next_confidence,
            target={"actor_id": ev.actor_id, "session_id": ev.session_id},
            automated=action in DESTRUCTIVE_ACTIONS,
            policy_version=self.version,
            trace=trace,
            notes=notes,
        )
