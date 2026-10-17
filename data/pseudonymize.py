"""
Pseudonymization for Threshold (M2).

actor_id = "U_" + first 12 hex chars of HMAC-SHA256(secret, user_id).
The secret comes from the env var THRESHOLD_HMAC_KEY and is never hard-coded.

Tests: python -m pytest data/pseudonymize.py   (or python data/pseudonymize.py)
"""

import hashlib
import hmac
import os

try:
    from schema import ACTOR_ID_PATTERN
except ImportError:
    from data.schema import ACTOR_ID_PATTERN

ENV_VAR = "THRESHOLD_HMAC_KEY"


def _get_key() -> bytes:
    key = os.environ.get(ENV_VAR)
    if not key:
        raise RuntimeError(
            f"Environment variable {ENV_VAR} is not set. Set it to a secret string "
            f"(PowerShell: $env:{ENV_VAR}='your-secret'; bash: export {ENV_VAR}=your-secret). "
            "It is deliberately never hard-coded."
        )
    return key.encode("utf-8")


def pseudonymize(user_id: str) -> str:
    """Map a raw user ID to a stable pseudonymous actor_id."""
    if user_id is None or str(user_id).strip() == "":
        raise ValueError("user_id must be a non-empty string")
    digest = hmac.new(_get_key(), str(user_id).encode("utf-8"), hashlib.sha256).hexdigest()
    return "U_" + digest[:12]


# --- Tests (pytest) ----------------------------------------------------------
def test_same_user_same_pseudonym():
    os.environ.setdefault(ENV_VAR, "test-key")
    assert pseudonymize("alice") == pseudonymize("alice")


def test_different_users_differ():
    os.environ.setdefault(ENV_VAR, "test-key")
    assert pseudonymize("alice") != pseudonymize("bob")


def test_format_matches_contract():
    os.environ.setdefault(ENV_VAR, "test-key")
    assert ACTOR_ID_PATTERN.match(pseudonymize("alice"))


def test_different_keys_differ():
    old = os.environ.get(ENV_VAR)
    try:
        os.environ[ENV_VAR] = "key-one"
        a = pseudonymize("alice")
        os.environ[ENV_VAR] = "key-two"
        b = pseudonymize("alice")
    finally:
        if old is None:
            os.environ.pop(ENV_VAR, None)
        else:
            os.environ[ENV_VAR] = old
    assert a != b


def test_missing_key_is_clear_error():
    old = os.environ.pop(ENV_VAR, None)
    try:
        try:
            pseudonymize("alice")
            raised = False
        except RuntimeError as e:
            raised = ENV_VAR in str(e)
    finally:
        if old is not None:
            os.environ[ENV_VAR] = old
    assert raised


if __name__ == "__main__":
    os.environ.setdefault(ENV_VAR, "self-test-key")
    for name in (test_same_user_same_pseudonym, test_different_users_differ,
                 test_format_matches_contract, test_different_keys_differ,
                 test_missing_key_is_clear_error):
        name()
        print("ok", name.__name__)
