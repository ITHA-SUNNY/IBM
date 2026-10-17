"""The evidence object: the contract between the model side and the policy side.

The model side (sequence + inference agents) produces one of these per actor
window. It says what the AI believes and why. It never says what to do.

Severity is deliberately NOT a field the model controls. The model supplies the
*context* (what resource, what action, privileged or not) and the policy agent
computes severity from fixed rules. If an upstream component sends its own
"severity" key it is kept for the audit trail but ignored for the decision.

`confidence` is the model's confidence in the current stage (`threat_type`).
`next_confidence` is its confidence in `predicted_next_stage`; it is optional
and falls back to `confidence` when absent.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .errors import EvidenceError

REQUIRED_FIELDS = (
    "actor_id",
    "timestamp",
    "threat_type",
    "confidence",
    "predicted_next_stage",
    "indicators",
    "resource_tier",
    "action",
    "is_privileged_actor",
)
OPTIONAL_FIELDS = ("session_id", "next_confidence")
KNOWN_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS


def canonical_json(obj: Any) -> str:
    """Stable JSON text, used for hashing and for the audit log.

    Same form as the shared audit contract (app/contracts.py): sorted keys,
    compact separators, UTF-8 kept as-is.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _probability(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_token(value: str) -> str:
    """'Lateral Movement' / 'lateral-movement' -> 'lateral_movement'."""
    return "_".join(value.strip().lower().replace("-", " ").split())


def _parse_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text[-1] in ("Z", "z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)  # raises ValueError if malformed
    else:
        raise ValueError("not a datetime or ISO-8601 string")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # naive timestamps are treated as UTC
    return dt.astimezone(timezone.utc).isoformat()


@dataclass
class EvidenceObject:
    actor_id: str
    timestamp: str
    threat_type: str
    confidence: float
    predicted_next_stage: str
    indicators: List[str]
    resource_tier: str
    action: str
    is_privileged_actor: bool
    session_id: Optional[str] = None
    next_confidence: Optional[float] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    @property
    def indicator_count(self) -> int:
        return len(self.indicators)

    @classmethod
    def from_dict(cls, data: Any) -> "EvidenceObject":
        """Validate and normalise. Raises EvidenceError listing every problem."""
        if not isinstance(data, dict):
            raise EvidenceError("evidence must be a JSON object")

        problems: List[str] = []
        missing = [name for name in REQUIRED_FIELDS if name not in data]
        if missing:
            problems.append("missing required field(s): " + ", ".join(missing))

        def text(name: str) -> Optional[str]:
            if name not in data:
                return None
            value = data[name]
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{name} must be a non-empty string")
                return None
            return value.strip()

        actor_id = text("actor_id")
        threat_type = text("threat_type")
        stage = text("predicted_next_stage")
        tier = text("resource_tier")
        action = text("action")

        session_id: Optional[str] = None
        if data.get("session_id") is not None:
            sid = data["session_id"]
            if not isinstance(sid, str) or not sid.strip():
                problems.append("session_id must be a non-empty string when provided")
            else:
                session_id = sid.strip()

        confidence: Optional[float] = None
        if "confidence" in data:
            if not _probability(data["confidence"]):
                problems.append("confidence must be a number between 0 and 1")
            else:
                confidence = float(data["confidence"])

        next_confidence: Optional[float] = None
        if data.get("next_confidence") is not None:
            if not _probability(data["next_confidence"]):
                problems.append("next_confidence must be a number between 0 and 1 when provided")
            else:
                next_confidence = float(data["next_confidence"])

        indicators: Optional[List[str]] = None
        if "indicators" in data:
            raw = data["indicators"]
            if not isinstance(raw, (list, tuple)) or any(
                not isinstance(i, str) or not i.strip() for i in raw
            ):
                problems.append("indicators must be a list of non-empty strings")
            else:
                # Distinct indicators only: repeating one signal must not inflate the count.
                seen, indicators = set(), []
                for item in raw:
                    clean = " ".join(item.split())
                    if clean.lower() not in seen:
                        seen.add(clean.lower())
                        indicators.append(clean)

        privileged: Optional[bool] = None
        if "is_privileged_actor" in data:
            if not isinstance(data["is_privileged_actor"], bool):
                problems.append("is_privileged_actor must be true or false")
            else:
                privileged = data["is_privileged_actor"]

        timestamp: Optional[str] = None
        if "timestamp" in data:
            try:
                timestamp = _parse_timestamp(data["timestamp"])
            except (ValueError, TypeError):
                problems.append("timestamp must be an ISO-8601 string or datetime")

        if problems:
            raise EvidenceError(problems)

        return cls(
            actor_id=actor_id,
            timestamp=timestamp,
            threat_type=normalize_token(threat_type),
            confidence=confidence,
            predicted_next_stage=normalize_token(stage),
            indicators=indicators,
            resource_tier=normalize_token(tier),
            action=normalize_token(action),
            is_privileged_actor=privileged,
            session_id=session_id,
            next_confidence=next_confidence,
            extras={k: v for k, v in data.items() if k not in KNOWN_FIELDS},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "next_confidence": self.next_confidence,
            "predicted_next_stage": self.predicted_next_stage,
            "indicators": list(self.indicators),
            "indicator_count": self.indicator_count,
            "resource_tier": self.resource_tier,
            "action": self.action,
            "is_privileged_actor": self.is_privileged_actor,
            "extras": dict(self.extras),
        }

    def digest(self) -> str:
        """SHA-256 of the normalised evidence; ties an audit entry to its input."""
        return sha256_hex(canonical_json(self.to_dict()))
