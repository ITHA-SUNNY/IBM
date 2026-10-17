"""
Threshold M3 Real Model Prediction Module

Loads trained models and Guo et al. calibration parameters to evaluate session telemetry.
Produces explainable, schema-validated evidence.json objects.
"""

import os
import sys
import json
import hashlib
import argparse
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
import joblib
from scipy.special import softmax

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

try:
    from features import extract_features_for_prefix, STANDARD_EVENT_TYPES, _is_failed, _is_privilege_change, _is_sensitive_access, _is_discovery
except ImportError:
    from model.features import extract_features_for_prefix, STANDARD_EVENT_TYPES, _is_failed, _is_privilege_change, _is_sensitive_access, _is_discovery

# Constants come from data/schema.py (features.py puts the repo root on sys.path)
from data.schema import STAGES, normalize_event_type  # noqa: E402


# Severity mapping per Section 5 specification
STAGE_BASE_SEVERITY: Dict[str, str] = {
    "BENIGN": "LOW",
    "INITIAL_ACCESS": "LOW",
    "CREDENTIAL_ACCESS": "MEDIUM",
    "DISCOVERY": "MEDIUM",
    "PRIVILEGE_ESCALATION": "HIGH",
    "LATERAL_MOVEMENT": "HIGH",
    "COLLECTION_EXFIL": "CRITICAL",
    "IMPACT": "CRITICAL"
}

ALLOWED_STAGES = list(STAGES)

ALLOWED_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _get_model_version(artifacts_dir: str) -> str:
    """Generate deterministic version string from model artifacts."""
    curr_path = os.path.join(artifacts_dir, "current_stage_model.joblib")
    if os.path.exists(curr_path):
        with open(curr_path, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()[:8]
        return f"m3-l16-{h}"
    return "m3-threshold-v1.0"


class ThresholdPredictor:
    """
    Singleton-style predictor that loads models and calibration once and caches them.
    """
    def __init__(self, artifacts_dir: Optional[str] = None):
        if not artifacts_dir:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            artifacts_dir = os.path.join(script_dir, "model_artifacts")

        self.artifacts_dir = artifacts_dir
        self.model_version = _get_model_version(artifacts_dir)
        
        # Load models
        curr_model_path = os.path.join(artifacts_dir, "current_stage_model.joblib")
        next_model_path = os.path.join(artifacts_dir, "next_stage_model.joblib")
        meta_path = os.path.join(artifacts_dir, "model_metadata.json")
        cal_path = os.path.join(artifacts_dir, "calibration.json")

        self.current_model = joblib.load(curr_model_path) if os.path.exists(curr_model_path) else None
        self.next_model = joblib.load(next_model_path) if os.path.exists(next_model_path) else None

        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                self.meta = json.load(f)
        else:
            self.meta = {}

        self.feature_names = self.meta.get("feature_names", [])
        self.window = self.meta.get("window_size", 10)

        # Load calibration temperatures
        if os.path.exists(cal_path):
            with open(cal_path, "r", encoding="utf-8") as f:
                cal_data = json.load(f)
            self.t_current = float(cal_data.get("current_stage", {}).get("temperature", 1.0))
            self.t_next = float(cal_data.get("next_stage", {}).get("temperature", 1.0))
        else:
            self.t_current = 1.0
            self.t_next = 1.0

        # Load schema
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence.schema.json")
        
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                self.schema = json.load(f)
        else:
            self.schema = None

    def validate_evidence(self, evidence: Dict[str, Any]):
        """Validate output evidence dict against JSON schema."""
        if self.schema and HAS_JSONSCHEMA:
            jsonschema.validate(instance=evidence, schema=self.schema)
        else:
            # Fallback strict programmatic assertion
            required = [
                "evidence_id", "actor", "session_id", "current_stage",
                "stage_confidence", "next_stage", "next_confidence",
                "severity", "indicators", "top_events", "model_version"
            ]
            for field in required:
                if field not in evidence:
                    raise ValueError(f"Missing required contract field: {field}")
            if evidence["current_stage"] not in ALLOWED_STAGES:
                raise ValueError(f"Invalid current_stage: {evidence['current_stage']}")
            if evidence["next_stage"] not in ALLOWED_STAGES:
                raise ValueError(f"Invalid next_stage: {evidence['next_stage']}")
            if evidence["severity"] not in ALLOWED_SEVERITIES:
                raise ValueError(f"Invalid severity: {evidence['severity']}")
            if not (0.0 <= evidence["stage_confidence"] <= 1.0):
                raise ValueError(f"Confidence out of range: {evidence['stage_confidence']}")
            if not (0.0 <= evidence["next_confidence"] <= 1.0):
                raise ValueError(f"Confidence out of range: {evidence['next_confidence']}")


# Global predictor cache keyed by artifacts directory
_PREDICTORS: Dict[str, ThresholdPredictor] = {}

def get_predictor(artifacts_dir: Optional[str] = None) -> ThresholdPredictor:
    global _PREDICTORS
    if artifacts_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        artifacts_dir = os.path.join(script_dir, "model_artifacts")
    
    key = os.path.abspath(artifacts_dir)
    if key not in _PREDICTORS:
        _PREDICTORS[key] = ThresholdPredictor(artifacts_dir=key)
    return _PREDICTORS[key]


def _is_sensitive_access_event(event_type: Any, sensitivity: Any) -> bool:
    """
    Sensitive access indicator: counts only DATASET_READ and DATASET_COPY
    events on HIGH-sensitivity resources (Fix 1).
    """
    et = normalize_event_type(event_type)
    s = str(sensitivity).strip().upper()
    return (et in ["DATASET_READ", "DATASET_COPY"]) and (s in ["HIGH", "CRITICAL", "RESTRICTED"])


def derive_indicators(prefix_df: pd.DataFrame, window: int = 10,
                      actor_history: Optional[set] = None) -> List[str]:
    """
    Extract rule-based indicator strings from window per Section 5 spec.
    Accurate and conservative: M4 needs >= 3 for revoke.

    actor_history: origins this actor used BEFORE this session (None/empty = unknown,
    in which case new_origin is never claimed).
    """
    if prefix_df is None or len(prefix_df) == 0:
        return []

    win_df = prefix_df.tail(window)
    indicators = []

    # 1. New origin: only claimed when we actually know this actor's history
    origins = prefix_df["origin"].dropna().astype(str).tolist() if "origin" in prefix_df else []
    if actor_history and any(o not in actor_history for o in origins):
        indicators.append("new_origin")

    # 2. Off hours activity
    off_hours = [str(x).strip().lower() in ["true", "1", "yes"] for x in win_df.get("off_hours", [])]
    if any(off_hours):
        indicators.append("off_hours_activity")

    # 3. MFA failure then success (MFA events only; a LOGON typo is not an MFA failure)
    outcomes = [str(o).upper() for o in prefix_df.get("outcome", [])]
    etypes = [normalize_event_type(e) for e in prefix_df.get("event_type", [])]
    has_mfa_fail = False
    has_mfa_success_after = False
    for et, oc in zip(etypes, outcomes):
        if et == "MFA":
            if "FAIL" in oc:
                has_mfa_fail = True
            elif ("SUCCESS" in oc) and has_mfa_fail:
                has_mfa_success_after = True
    if has_mfa_success_after:
        indicators.append("mfa_failure_then_success")

    # 4. Privilege change
    priv_events = [
        _is_privilege_change(r.get("event_type", ""), r.get("resource", ""))
        for _, r in win_df.iterrows()
    ]
    if any(priv_events):
        indicators.append("privilege_change")

    # 5. Sensitive access: only DATASET_READ and DATASET_COPY on HIGH sensitivity resources
    sens_events = [
        _is_sensitive_access_event(r.get("event_type", ""), r.get("sensitivity", ""))
        for _, r in win_df.iterrows()
    ]
    if any(sens_events):
        indicators.append("sensitive_access")

    # 6. Discovery sweep (>= 2 discovery events in window)
    disc_count = sum(_is_discovery(r.get("event_type", ""), r.get("resource", ""))
                     for _, r in win_df.iterrows())
    if disc_count >= 2:
        indicators.append("discovery_sweep")

    return sorted(list(set(indicators)))


def extract_top_events(prefix_df: pd.DataFrame, window: int = 10) -> List[str]:
    """
    Select up to 5 contributing event_ids ranked by risk score and recency.
    """
    if prefix_df is None or len(prefix_df) == 0:
        return []

    win_df = prefix_df.tail(window).copy()
    scored_events = []

    for i, (_, row) in enumerate(win_df.iterrows()):
        eid = str(row.get("event_id", f"evt-{i}"))
        et = row.get("event_type", "")
        res = row.get("resource", "")
        sens = row.get("sensitivity", "")
        oc = row.get("outcome", "")

        score = 1
        if _is_privilege_change(et, res):
            score += 10
        if _is_sensitive_access_event(et, sens):
            score += 8
        if _is_failed(oc):
            score += 5
        if _is_discovery(et, res):
            score += 3

        # Add small recency bonus so recent critical events rank highest
        score += (i * 0.1)
        scored_events.append((score, eid))

    # Sort by score descending
    scored_events.sort(key=lambda x: x[0], reverse=True)
    top_5 = [eid for _, eid in scored_events[:5]]
    return top_5


def derive_severity(current_stage: str, indicators: List[str]) -> str:
    """
    Derive severity separate from confidence per Section 5:
    BENIGN/INITIAL_ACCESS -> LOW
    DISCOVERY -> MEDIUM
    PRIVILEGE_ESCALATION/LATERAL_MOVEMENT -> HIGH
    COLLECTION_EXFIL/IMPACT or priv-esc plus sensitive access -> CRITICAL
    """
    if current_stage in ["COLLECTION_EXFIL", "IMPACT"]:
        return "CRITICAL"
    if current_stage in ["PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT"] and ("sensitive_access" in indicators):
        return "CRITICAL"
    
    return STAGE_BASE_SEVERITY.get(current_stage, "LOW")


def predict_session(
    events_df: Any,
    actor_history: Optional[set] = None,
    artifacts_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Predict attack stage and calibrated confidence for a single session prefix.
    
    Args:
        events_df: pandas DataFrame or list of dicts.
        actor_history: optional set of origins known for this actor prior to this session.
        artifacts_dir: optional path to model artifacts directory.
        
    Returns:
        dict: Schema-validated evidence object with all 11 required contract fields.
    """
    predictor = get_predictor(artifacts_dir=artifacts_dir)

    # Graceful handling of empty/malformed input
    if events_df is None or (hasattr(events_df, "empty") and events_df.empty) or (isinstance(events_df, list) and len(events_df) == 0):
        evidence = {
            "evidence_id": "ev-benign-empty-001",
            "actor": "U_UNKNOWN",
            "session_id": "sess-default",
            "current_stage": "BENIGN",
            "stage_confidence": 0.50,
            "next_stage": "BENIGN",
            "next_confidence": 0.50,
            "severity": "LOW",
            "indicators": [],
            "top_events": [],
            "model_version": predictor.model_version
        }
        predictor.validate_evidence(evidence)
        return evidence

    if not isinstance(events_df, pd.DataFrame):
        prefix_df = pd.DataFrame(events_df)
    else:
        prefix_df = events_df.copy()

    # Sort chronologically
    if "timestamp" in prefix_df:
        prefix_df = prefix_df.sort_values("timestamp")

    last_row = prefix_df.iloc[-1]
    session_id = str(last_row.get("session_id", "sess-unknown"))
    actor = str(last_row.get("actor_id", "U_unknown"))
    event_idx = len(prefix_df)

    # 1. Feature extraction. Origins known to the model = this actor's earlier history plus
    #    earlier events of this session (mirrors build_windows in training).
    known_origins = set(actor_history or ())
    if "origin" in prefix_df and len(prefix_df) > 1:
        known_origins |= set(prefix_df["origin"].iloc[:-1].dropna().astype(str).str.strip())
    feat_dict = extract_features_for_prefix(
        prefix_df=prefix_df,
        actor_historical_origins=known_origins,
        window=predictor.window
    )
    feat_df = pd.DataFrame([feat_dict])
    if predictor.feature_names:
        feat_df = feat_df.reindex(columns=predictor.feature_names, fill_value=0)

    # 2. Current Head Prediction + Temperature Scaling
    if predictor.current_model is not None:
        curr_probs_raw = predictor.current_model.predict_proba(feat_df)[0]
        curr_classes = list(predictor.current_model.classes_)
        curr_logits = np.log(np.clip(curr_probs_raw, 1e-12, 1.0))
        curr_probs_cal = softmax(curr_logits / max(predictor.t_current, 1e-6))
        
        best_curr_idx = int(np.argmax(curr_probs_cal))
        current_stage = str(curr_classes[best_curr_idx])
        stage_confidence = float(np.max(curr_probs_cal))
    else:
        current_stage = "BENIGN"
        stage_confidence = 0.50

    # 3. Next Head Prediction + Temperature Scaling
    if predictor.next_model is not None:
        next_probs_raw = predictor.next_model.predict_proba(feat_df)[0]
        next_classes = list(predictor.next_model.classes_)
        next_logits = np.log(np.clip(next_probs_raw, 1e-12, 1.0))
        next_probs_cal = softmax(next_logits / max(predictor.t_next, 1e-6))
        
        best_next_idx = int(np.argmax(next_probs_cal))
        next_stage = str(next_classes[best_next_idx])
        next_confidence = float(np.max(next_probs_cal))
    else:
        next_stage = "BENIGN"
        next_confidence = 0.50

    # Ensure stages match 8 contract labels
    if current_stage not in ALLOWED_STAGES:
        current_stage = "BENIGN"
    if next_stage not in ALLOWED_STAGES:
        next_stage = "BENIGN"

    # 4. Indicators and Top Events
    indicators = derive_indicators(prefix_df, window=predictor.window, actor_history=actor_history)
    top_events = extract_top_events(prefix_df, window=predictor.window)

    # 5. Severity derivation
    severity = derive_severity(current_stage, indicators)

    evidence: Dict[str, Any] = {
        "evidence_id": f"ev-{session_id}-{event_idx}",
        "actor": actor,
        "session_id": session_id,
        "current_stage": current_stage,
        "stage_confidence": round(float(np.clip(stage_confidence, 0.0, 1.0)), 4),
        "next_stage": next_stage,
        "next_confidence": round(float(np.clip(next_confidence, 0.0, 1.0)), 4),
        "severity": severity,
        "indicators": indicators,
        "top_events": top_events,
        "model_version": predictor.model_version
    }

    # Validate output contract
    predictor.validate_evidence(evidence)
    return evidence


def predict_stream(
    events_df: Any,
    artifacts_dir: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Predict evidence after each event in a session (event-by-event prefix replay).
    
    Args:
        events_df: pandas DataFrame or list of dicts.
        artifacts_dir: optional path to model artifacts directory.
        
    Returns:
        List of validated evidence objects, one per event in the stream.
    """
    if events_df is None or (hasattr(events_df, "empty") and events_df.empty) or (isinstance(events_df, list) and len(events_df) == 0):
        return [predict_session(None, artifacts_dir=artifacts_dir)]

    if not isinstance(events_df, pd.DataFrame):
        df = pd.DataFrame(events_df)
    else:
        df = events_df.copy()

    results: List[Any] = [None] * len(df)
    actor_history: Dict[str, set] = {}
    df = df.copy()
    df["__orig_pos__"] = np.arange(len(df))
    session_groups = df.groupby("session_id", sort=False)
    for session_id, s_df in session_groups:
        s_len = len(s_df)
        actor = str(s_df.iloc[0].get("actor_id", ""))
        hist = actor_history.setdefault(actor, set())
        orig_positions = s_df["__orig_pos__"].tolist()
        for i in range(1, s_len + 1):
            prefix = s_df.iloc[:i]
            ev = predict_session(prefix, actor_history=set(hist), artifacts_dir=artifacts_dir)
            results[orig_positions[i - 1]] = ev
        if "origin" in s_df:
            hist |= set(s_df["origin"].dropna().astype(str).str.strip())

    return results


def main():
    parser = argparse.ArgumentParser(description="Threshold M3 Real Inference CLI")
    parser.add_argument("--events", required=True, help="Path to events CSV file")
    parser.add_argument("--out", required=False, help="Path to write output evidence JSON")
    parser.add_argument("--artifacts", required=False, default=None, help="Path to model artifacts directory")

    args = parser.parse_args()

    if not os.path.exists(args.events):
        print(f"Error: file not found: {args.events}", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(args.events)
    evidence_list = predict_stream(df, artifacts_dir=args.artifacts)

    output_json = json.dumps(evidence_list, indent=2)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"Successfully generated and validated {len(evidence_list)} evidence records to {args.out}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
