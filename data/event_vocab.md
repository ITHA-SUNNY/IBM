# Threshold event vocabulary (M2)

Mirror of [schema.py](schema.py), which is the single source of truth. If the two ever disagree, `schema.py` wins.

## Columns (exact order)

`event_id, timestamp, system_id, actor_id, session_id, event_type, outcome, resource, sensitivity, origin, off_hours, stage_label, scenario_id`

## Allowed values

| Column | Values |
|---|---|
| timestamp | ISO-8601 UTC, e.g. `2026-03-02T09:14:05Z` |
| event_type | `LOGON, LOGOFF, MFA, JOB_SUBMIT, PASSWORD_CHANGE, DATASET_LIST, RACF_LISTUSER, ALTUSER_SPECIAL, PERMIT, DATASET_READ, DATASET_COPY` |
| outcome | `SUCCESS, FAILURE` |
| sensitivity | `LOW, MEDIUM, HIGH` |
| origin | e.g. `NET_KNOWN_03`, `NET_NEW_17` |
| off_hours | `0` or `1` (generator: UTC hour < 6 or >= 20 is `1`) |
| actor_id | `U_` + 12 lowercase hex chars (HMAC-SHA256 pseudonym), regex `^U_[0-9a-f]{12}$` |
| stage_label | `BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT` |
| scenario_id | `benign, attack_v1, attack_v2, lookalike_v1, ...` (analysis only; never a model feature) |

Groupings used by features: privilege change = `ALTUSER_SPECIAL`, `PERMIT`; discovery = `DATASET_LIST`, `RACF_LISTUSER`.

## Scenario sequences

Every actor in an attack or look-alike scenario also has one earlier `benign` history session from a known origin, so "new origin" is learnable. Noise events (0-5, e.g. `JOB_SUBMIT`, low-sensitivity `DATASET_READ`) are inserted after the first event and take the stage label of the event before them.

### benign

Routine logons from the user's known origin, business hours (some night batch jobs, `off_hours=1`), occasional typo.

| # | event_type | outcome | sensitivity | stage_label |
|---|---|---|---|---|
| 1 | `LOGON` (a failed `LOGON` typo precedes it occasionally) | SUCCESS | LOW | BENIGN |
| 2 | `MFA` (optional) | SUCCESS | LOW | BENIGN |
| 3..n | `JOB_SUBMIT`, `DATASET_READ` (LOW/MEDIUM; HIGH rarely), single `DATASET_LIST`/`RACF_LISTUSER`, `DATASET_COPY`, `PASSWORD_CHANGE` | SUCCESS | LOW/MEDIUM | BENIGN |
| last | `LOGOFF` | SUCCESS | LOW | BENIGN |

### attack_v1

| # | event_type | outcome | origin | stage_label |
|---|---|---|---|---|
| 1 | `LOGON` | SUCCESS | **new** (`NET_NEW_*`) | INITIAL_ACCESS |
| 2..k+1 | `MFA` x1-3 | FAILURE | new | CREDENTIAL_ACCESS |
| k+2 | `MFA` | SUCCESS | new | CREDENTIAL_ACCESS |
| next 2-6 | `DATASET_LIST` / `RACF_LISTUSER` | SUCCESS | new | DISCOVERY |
| next | `ALTUSER_SPECIAL` (HIGH, rarely MEDIUM) | SUCCESS | new | PRIVILEGE_ESCALATION |
| next 1-3 | `DATASET_READ` (HIGH) | SUCCESS | new | COLLECTION_EXFIL |

### attack_v2

Same as attack_v1 up to `ALTUSER_SPECIAL`, then:

| # | event_type | outcome | system_id | stage_label |
|---|---|---|---|---|
| next | `LOGON` | SUCCESS | **second system** | LATERAL_MOVEMENT |
| optional | `JOB_SUBMIT` (MEDIUM) | SUCCESS | second system | LATERAL_MOVEMENT |
| next 1-3 | `DATASET_READ` (HIGH), then optional `DATASET_COPY` (HIGH) | SUCCESS | second system | COLLECTION_EXFIL |
| optional (50%) | `JOB_SUBMIT` (HIGH, destructive job) | SUCCESS | second system | IMPACT |

### lookalike_v1

A legitimate admin: 02:00 UTC, known origin, no failures, one `ALTUSER_SPECIAL`, a few routine reads. **All events labeled `BENIGN`.** The same `ALTUSER_SPECIAL` is `PRIVILEGE_ESCALATION` in the attacks, so the model must use context (origin, failures, discovery sweep). Sensitivity of the `ALTUSER_SPECIAL` is HIGH or MEDIUM at random in both scenarios so sensitivity alone does not give the answer away.

| # | event_type | outcome | origin | stage_label |
|---|---|---|---|---|
| 1 | `LOGON` | SUCCESS | known | BENIGN |
| 2 | `MFA` | SUCCESS | known | BENIGN |
| 3 | `ALTUSER_SPECIAL` | SUCCESS | known | BENIGN |
| 4-6 | `DATASET_READ` (LOW/MEDIUM) / `JOB_SUBMIT` | SUCCESS | known | BENIGN |
| last | `LOGOFF` | SUCCESS | known | BENIGN |

## Legacy mapping (old names to new names)

Found in `model/features.py`, `model/predict.py` and `model/sample_events.csv`. Applied through `LEGACY_TO_NEW` in `schema.py`.

| Old name | New name | Note |
|---|---|---|
| `LOGON_ATTEMPT` | `LOGON` | |
| `LOGOFF` | `LOGOFF` | unchanged |
| `MFA_AUTH` | `MFA` | |
| `SUBMIT_JOB` | `JOB_SUBMIT` | |
| `BATCH_INIT` | `JOB_SUBMIT` | a batch job start is a job submission |
| `LIST_DATASETS` | `DATASET_LIST` | |
| `LIST_USERS` | `RACF_LISTUSER` | |
| `LIST_PRIVILEGES` | `RACF_LISTUSER` | LISTUSER shows a user's privileges |
| `ALTUSER_SPECIAL` | `ALTUSER_SPECIAL` | unchanged |
| `CONNECT_GROUP` | `PERMIT` | both grant access rights; medium confidence, please confirm |
| `READ_DATASET` | `DATASET_READ` | |
| `FTP_TRANSFER` | `DATASET_COPY` | mapped per user decision (closest match for data leaving system) |

### Dropped Legacy Event Types (no sensible match in 11-type vocabulary)

Dropped per user decision (from legacy sample file only; not in schema):
`REVOKE_SPECIAL`, `EDIT_DATASET`, `WRITE_DATASET`, `QUERY_JOB_STATUS`, `VIEW_SYSLOG`, `RESTART_SERVICE`, `READ_SPOOL_OUTPUT`, `ALLOC_TEMP_DATASET`, `SORT_EXEC`, `WRITE_LOG`, `BATCH_PURGE_TEMP`, `BATCH_TERMINATE`, `ACCESS_ISPF`

