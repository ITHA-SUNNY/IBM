"""Threshold events.csv single source of truth (M2), supplied by Vinayak."""
import re
from datetime import datetime, timezone

COLUMNS = [
    "event_id", "timestamp", "system_id", "actor_id", "session_id",
    "event_type", "outcome", "resource", "sensitivity", "origin",
    "off_hours", "stage_label", "scenario_id",
]
STAGES = ["BENIGN", "INITIAL_ACCESS", "CREDENTIAL_ACCESS", "DISCOVERY",
          "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "COLLECTION_EXFIL", "IMPACT"]
EVENT_TYPES = ["LOGON", "LOGOFF", "MFA", "JOB_SUBMIT", "PASSWORD_CHANGE",
               "DATASET_LIST", "RACF_LISTUSER", "ALTUSER_SPECIAL", "PERMIT",
               "DATASET_READ", "DATASET_COPY"]
OUTCOMES = ["SUCCESS", "FAILURE"]
SENSITIVITY = ["LOW", "MEDIUM", "HIGH"]
OFF_HOURS = [0, 1]
ACTOR_ID_REGEX = r"^U_[0-9a-f]{12}$"
ACTOR_ID_PATTERN = re.compile(ACTOR_ID_REGEX)
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SCENARIO_IDS = ["benign", "attack_v1", "attack_v2", "lookalike_v1"]
PRIVILEGE_CHANGE_TYPES = ["ALTUSER_SPECIAL", "PERMIT"]
DISCOVERY_TYPES = ["DATASET_LIST", "RACF_LISTUSER"]
OFF_HOURS_START_HOUR = 20
OFF_HOURS_END_HOUR = 6
LEGACY_TO_NEW = {
    "LOGON_ATTEMPT": "LOGON", "LOGOFF": "LOGOFF", "MFA_AUTH": "MFA",
    "SUBMIT_JOB": "JOB_SUBMIT", "BATCH_INIT": "JOB_SUBMIT",
    "LIST_DATASETS": "DATASET_LIST", "LIST_USERS": "RACF_LISTUSER",
    "LIST_PRIVILEGES": "RACF_LISTUSER", "ALTUSER_SPECIAL": "ALTUSER_SPECIAL",
    "CONNECT_GROUP": "PERMIT", "READ_DATASET": "DATASET_READ",
    "FTP_TRANSFER": "DATASET_COPY",
}
LEGACY_UNMAPPED = [
    "REVOKE_SPECIAL", "EDIT_DATASET", "WRITE_DATASET", "QUERY_JOB_STATUS",
    "VIEW_SYSLOG", "RESTART_SERVICE", "READ_SPOOL_OUTPUT", "ALLOC_TEMP_DATASET",
    "SORT_EXEC", "WRITE_LOG", "BATCH_PURGE_TEMP", "BATCH_TERMINATE", "ACCESS_ISPF",
]


def normalize_event_type(name):
    name = str(name).strip().upper()
    return LEGACY_TO_NEW.get(name, name)


def is_off_hours(ts):
    if isinstance(ts, str):
        ts = datetime.strptime(ts, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    return int(ts.hour < OFF_HOURS_END_HOUR or ts.hour >= OFF_HOURS_START_HOUR)
