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
from typing import Any, Dict, List, Optional

from .errors import PolicyConfigError
from .evidence import EvidenceObject, canonical_json, normalize_token, sha256_hex
from .severity import SEVERITY_LEVELS, SeverityModel

ACTIONS = ("LOG_ONLY", "EARLY_WARNING", "ALERT_ANALYST", "REVOKE_SESSION", "LOCK_CREDENTIALS")
DESTRUCTIVE_ACTIONS = frozenset({"REVOKE_SESSION", "LOCK_CREDENTIALS"})

# Guardrails enforced when rules.json is loaded. Whoever edits the config cannot
# make the system take a destructive action on thin evidence.
DESTRUCTIVE_MIN_CONFIDENCE_FLOOR = 0.80
DESTRUCTIVE_MIN_INDICATORS_FLOOR = 2

CONDITION_KEYS = (
    "severity_in",
    "min_confidence",
    "max_confidence_exclusive",
    "min_indicators",
    "predicted_next_stage_in",
)

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
    for key in ("min_confidence", "max_confidence_exclusive"):
        if key in when and (not _is_number(when[key]) or not 0.0 <= when[key] <= 1.0):
            problems.append(f"{where}.{key} must be a number between 0 and 1")
    if "min_indicators" in when:
        n = when["min_indicators"]
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            problems.append(f"{where}.min_indicators must be a non-negative integer")
    if "predicted_next_stage_in" in when:
        stages = when["predicted_next_stage_in"]
        if not isinstance(stages, list) or not stages or any(not isinstance(s, str) or not s.strip() for s in stages):
            problems.append(f"{where}.predicted_next_stage_in must be a non-empty list of strings")

    if action in DESTRUCTIVE_ACTIONS:
        if "severity_in" not in when:
            problems.append(f"{where} ({action}) must set severity_in")
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


def _normalise_when(when: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(when)
    if "predicted_next_stage_in" in out:
        out["predicted_next_stage_in"] = [normalize_token(s) for s in out["predicted_next_stage_in"]]
    return out


class Policy:
    def __init__(self, config: Dict[str, Any]) -> None:
        if not isinstance(config, dict):
            raise PolicyConfigError("config must be a JSON object")
        problems: List[str] = []

        version = config.get("policy_version")
        if not isinstance(version, str) or not version.strip():
            problems.append("policy_version must be a non-empty string")

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
                    validated.append({**rule, "when": _normalise_when(rule["when"])})

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
        self.config_hash: str = sha256_hex(canonical_json(config))

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
        if "min_indicators" in when and facts["indicator_count"] < when["min_indicators"]:
            failed.append(f"indicators {facts['indicator_count']} < {when['min_indicators']} required")
        if "predicted_next_stage_in" in when and facts["predicted_next_stage"] not in when["predicted_next_stage_in"]:
            failed.append(
                f"predicted stage '{facts['predicted_next_stage']}' not in {when['predicted_next_stage_in']}"
            )
        return failed

    def evaluate(self, ev: EvidenceObject) -> Decision:
        """Raises EvidenceError if the evidence uses a tier or action the policy does not know."""
        severity, score = self.severity_model.compute(ev.resource_tier, ev.action, ev.is_privileged_actor)
        facts = {
            "severity": severity,
            "confidence": ev.confidence,
            "indicator_count": ev.indicator_count,
            "predicted_next_stage": ev.predicted_next_stage,
        }

        notes: List[str] = []
        if "severity" in ev.extras:
            notes.append(
                "Upstream-supplied 'severity' was ignored: severity is computed here from "
                "resource_tier, action and is_privileged_actor."
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
            indicator_count=ev.indicator_count,
            predicted_next_stage=ev.predicted_next_stage,
            target={"actor_id": ev.actor_id, "session_id": ev.session_id},
            automated=action in DESTRUCTIVE_ACTIONS,
            policy_version=self.version,
            trace=trace,
            notes=notes,
        )
