"""
Threshold: events.csv schema constants (SINGLE SOURCE OF TRUTH, owner: M2).

Mirrored in data/event_vocab.md. Nobody else may redefine these lists:
data/generate.py, data/validate_events.py, model/features.py, model/predict.py
and all adapters must import from here.
"""

import re
from datetime import datetime, timezone

# --- Contract: events.csv (exact column names and order) ---------------------
COLUMNS = [
    "event_id", "timestamp", "system_id", "actor_id", "session_id",
    "event_type", "outcome", "resource", "sensitivity", "origin",
    "off_hours", "stage_label", "scenario_id",
]

# --- Stages (fixed 8; order = progression order) -----------------------------
STAGES = [
    "BENIGN",
    "INITIAL_ACCESS",
    "CREDENTIAL_ACCESS",
    "DISCOVERY",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "COLLECTION_EXFIL",
    "IMPACT",
]

# --- Allowed values ----------------------------------------------------------
EVENT_TYPES = [
    "LOGON", "LOGOFF", "MFA", "JOB_SUBMIT", "PASSWORD_CHANGE",
    "DATASET_LIST", "RACF_LISTUSER", "ALTUSER_SPECIAL", "PERMIT",
    "DATASET_READ", "DATASET_COPY",
]
OUTCOMES = ["SUCCESS", "FAILURE"]
SENSITIVITY = ["LOW", "MEDIUM", "HIGH"]
OFF_HOURS = [0, 1]

# actor_id = "U_" + first 12 hex chars of HMAC-SHA256 (never a raw user ID)
ACTOR_ID_REGEX = r"^U_[0-9a-f]{12}$"
ACTOR_ID_PATTERN = re.compile(ACTOR_ID_REGEX)

# timestamp = ISO-8601 UTC, e.g. 2026-03-02T09:14:05Z
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# scenario_id values (analysis only; the model must NEVER use it as a feature)
SCENARIO_IDS = ["benign", "attack_v1", "attack_v2", "lookalike_v1"]
# Hard-variant, adapter and other scenario ids are free-form but must be non-empty.

# --- Event groupings shared by features / predict / generator ----------------
PRIVILEGE_CHANGE_TYPES = ["ALTUSER_SPECIAL", "PERMIT"]
DISCOVERY_TYPES = ["DATASET_LIST", "RACF_LISTUSER"]

# Off-hours definition used by the generator: UTC hour < START_END or >= START
OFF_HOURS_START_HOUR = 20
OFF_HOURS_END_HOUR = 6

# --- Legacy vocabulary (model/sample_events.csv, old features.py) ------------
# Maps each OLD event type name to the closest NEW name. Old names with no
# sensible match are deliberately absent here and listed under UNMAPPED in
# data/event_vocab.md (decision needed; do not guess).
LEGACY_TO_NEW = {
    "LOGON_ATTEMPT": "LOGON",
    "LOGOFF": "LOGOFF",
    "MFA_AUTH": "MFA",
    "SUBMIT_JOB": "JOB_SUBMIT",
    "BATCH_INIT": "JOB_SUBMIT",          # a batch job starting is a job submission
    "LIST_DATASETS": "DATASET_LIST",
    "LIST_USERS": "RACF_LISTUSER",
    "LIST_PRIVILEGES": "RACF_LISTUSER",  # LISTUSER shows a user's attributes/privileges
    "ALTUSER_SPECIAL": "ALTUSER_SPECIAL",
    "CONNECT_GROUP": "PERMIT",           # both grant access rights (medium confidence)
    "READ_DATASET": "DATASET_READ",
    "FTP_TRANSFER": "DATASET_COPY",      # closest match for data leaving the system
}

# Old names with no sensible new equivalent (dropped per user decision)
LEGACY_UNMAPPED = [
    "REVOKE_SPECIAL", "EDIT_DATASET", "WRITE_DATASET", "QUERY_JOB_STATUS",
    "VIEW_SYSLOG", "RESTART_SERVICE", "READ_SPOOL_OUTPUT", "ALLOC_TEMP_DATASET",
    "SORT_EXEC", "WRITE_LOG", "BATCH_PURGE_TEMP", "BATCH_TERMINATE",
    "ACCESS_ISPF",
]


def normalize_event_type(name):
    """Return the new-vocabulary name for an event type.

    New names pass through; mapped legacy names are translated; unmapped
    legacy or unknown names are returned unchanged (never guessed).
    """
    name = str(name).strip().upper()
    return LEGACY_TO_NEW.get(name, name)


def is_off_hours(ts):
    """Return 1 if a UTC datetime falls in the off-hours window, else 0."""
    if isinstance(ts, str):
        ts = datetime.strptime(ts, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    return int(ts.hour < OFF_HOURS_END_HOUR or ts.hour >= OFF_HOURS_START_HOUR)
