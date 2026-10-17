"""Severity: what is at stake if this is real.

Rule-based and independent of the model. It looks at the resource tier, the
action and whether the actor is privileged. It never sees model confidence, so
confidence can never raise or lower severity.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .errors import EvidenceError, PolicyConfigError
from .evidence import normalize_token

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class SeverityModel:
    def __init__(self, cfg: Dict) -> None:
        problems: List[str] = []
        self.tiers: Dict[str, int] = {}
        self.actions: Dict[str, int] = {}
        self.privileged_bonus = 0
        self.bands: List[Tuple[str, int]] = []

        if not isinstance(cfg, dict):
            raise PolicyConfigError("'severity' must be an object")

        for key, target in (("resource_tiers", self.tiers), ("action_weights", self.actions)):
            block = cfg.get(key)
            if not isinstance(block, dict) or not block:
                problems.append(f"severity.{key} must be a non-empty object")
                continue
            for name, weight in block.items():
                if not _is_int(weight) or weight < 0:
                    problems.append(f"severity.{key}.{name} must be a non-negative integer")
                else:
                    target[normalize_token(name)] = weight

        bonus = cfg.get("privileged_actor_bonus", 0)
        if not _is_int(bonus) or bonus < 0:
            problems.append("severity.privileged_actor_bonus must be a non-negative integer")
        else:
            self.privileged_bonus = bonus

        bands = cfg.get("bands")
        if not isinstance(bands, dict) or not bands:
            problems.append("severity.bands must be a non-empty object")
        else:
            parsed: Dict[str, int] = {}
            for label, threshold in bands.items():
                if label not in SEVERITY_LEVELS[1:]:
                    problems.append(f"severity.bands has unknown level '{label}'")
                elif not _is_int(threshold):
                    problems.append(f"severity.bands.{label} must be an integer")
                else:
                    parsed[label] = threshold
            ordered = [parsed[l] for l in SEVERITY_LEVELS[1:] if l in parsed]
            if any(a >= b for a, b in zip(ordered, ordered[1:])):
                problems.append("severity.bands thresholds must rise MEDIUM < HIGH < CRITICAL")
            self.bands = sorted(parsed.items(), key=lambda kv: kv[1], reverse=True)

        if problems:
            raise PolicyConfigError(problems)

    def compute(self, resource_tier: str, action: str, is_privileged_actor: bool) -> Tuple[str, int]:
        problems = []
        if resource_tier not in self.tiers:
            problems.append(
                f"unknown resource_tier '{resource_tier}' (known: {', '.join(sorted(self.tiers))})"
            )
        if action not in self.actions:
            problems.append(f"unknown action '{action}' (known: {', '.join(sorted(self.actions))})")
        if problems:
            raise EvidenceError(problems)

        score = self.tiers[resource_tier] + self.actions[action]
        if is_privileged_actor:
            score += self.privileged_bonus
        for label, threshold in self.bands:
            if score >= threshold:
                return label, score
        return "LOW", score

    def highest_risk_event(self, events: List[Dict]) -> Tuple[str, str, Optional[str]]:
        """(resource_tier, action, event_id) of the highest-risk event in a window.

        Events use the events.csv contract (event_type, sensitivity, outcome).
        Successful events are preferred; if none succeeded, all are considered.
        Ties go to the latest event. Unknown vocabulary raises EvidenceError, so
        the caller fails safe rather than under-scoring an unrecognised event.
        """
        if not isinstance(events, list) or not events:
            raise EvidenceError("no observed events to judge severity on")
        problems: List[str] = []
        scored = []
        for e in events:
            if not isinstance(e, dict):
                problems.append("each event must be a JSON object")
                continue
            tier = normalize_token(str(e.get("sensitivity") or ""))
            action = normalize_token(str(e.get("event_type") or ""))
            if tier not in self.tiers:
                problems.append(f"event {e.get('event_id')}: unknown sensitivity '{e.get('sensitivity')}'")
            if action not in self.actions:
                problems.append(f"event {e.get('event_id')}: unknown event_type '{e.get('event_type')}'")
            if tier in self.tiers and action in self.actions:
                ok = str(e.get("outcome", "")).strip().upper() == "SUCCESS"
                scored.append((ok, self.tiers[tier] + self.actions[action], tier, action, e.get("event_id")))
        if problems:
            raise EvidenceError(problems)
        pool = [s for s in scored if s[0]] or scored
        best = None
        for item in pool:
            if best is None or item[1] >= best[1]:
                best = item
        return best[2], best[3], best[4]
