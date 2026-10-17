"""Unit and integration tests for M5 (UI, console, bridge, contracts, and audit verifier).

Run with:
    python -m unittest tests/test_m5_console.py
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

# Add project root to path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.contracts import (
    STAGES,
    EVENTS_COLUMNS,
    EVIDENCE_FIELDS,
    AUDIT_FIELDS,
    ZERO_HASH,
    compute_entry_hash,
    entry_hash_candidates,
    canonical_json,
    preview_decision,
)
from app.bridge import (
    load_console_data,
    pick_sessions,
    make_playlist,
    compute_view,
    decide,
    AuditStore,
)
from app.sysinfo import detect_platform, PlatformInfo


class TestContracts(unittest.TestCase):
    """Verify shared contracts, fixed stages, and canonical hashing."""

    def test_eight_fixed_stages(self):
        expected_stages = [
            "BENIGN",
            "INITIAL_ACCESS",
            "CREDENTIAL_ACCESS",
            "DISCOVERY",
            "PRIVILEGE_ESCALATION",
            "LATERAL_MOVEMENT",
            "COLLECTION_EXFIL",
            "IMPACT",
        ]
        self.assertEqual(STAGES, expected_stages)
        self.assertEqual(len(STAGES), 8)

    def test_contract_column_names(self):
        self.assertIn("stage_label", EVENTS_COLUMNS)
        self.assertIn("scenario_id", EVENTS_COLUMNS)
        self.assertIn("current_stage", EVIDENCE_FIELDS)
        self.assertIn("next_stage", EVIDENCE_FIELDS)
        self.assertIn("stage_confidence", EVIDENCE_FIELDS)
        self.assertIn("next_confidence", EVIDENCE_FIELDS)
        self.assertIn("prev_hash", AUDIT_FIELDS)
        self.assertIn("entry_hash", AUDIT_FIELDS)

    def test_canonical_json_determinism(self):
        obj1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
        obj2 = {"a": 1, "nested": {"y": 20, "z": 10}, "b": 2}
        self.assertEqual(canonical_json(obj1), canonical_json(obj2))

    def test_compute_entry_hash(self):
        prev = ZERO_HASH
        entry = {
            "seq": 1,
            "ts": "2026-10-17T09:14:02Z",
            "evidence_id": "ev-0001",
            "rule_fired": "P9",
            "action": "LOG_ONLY",
            "policy_version": "policy-v0.1.0-3f9c",
            "prev_hash": prev,
        }
        h1 = compute_entry_hash(prev, entry)
        self.assertEqual(len(h1), 64)
        candidates = entry_hash_candidates(prev, entry)
        self.assertIn(h1, candidates)


class TestPolicyRules(unittest.TestCase):
    """Verify that policy rules enforce the trust boundary (AI predicts, policy decides)."""

    def test_attack_scenario_progression(self):
        data = load_console_data("stub")

        # Step 4 (ev-0004): Early warning on forecast of PRIVILEGE_ESCALATION
        ev4 = [e for e in data.evidence if e.get("evidence_id") == "ev-0004"][0]
        d4 = decide(data, ev4)
        self.assertEqual(d4["action"], "EARLY_WARNING")
        self.assertEqual(d4["rule_fired"], "P7")

        # Step 6 (ev-0006): Revoke session on CRITICAL + Special privilege escalation
        ev6 = [e for e in data.evidence if e.get("evidence_id") == "ev-0006"][0]
        d6 = decide(data, ev6)
        self.assertEqual(d6["action"], "REVOKE_SESSION")
        self.assertEqual(d6["rule_fired"], "P4")

    def test_lookalike_safety_abstention(self):
        data = load_console_data("stub")

        # Look-alike session s2 (ev-0011): High severity but uncertain (conformal set >= 3)
        ev11 = [e for e in data.evidence if e.get("evidence_id") == "ev-0011"][0]
        d11 = decide(data, ev11)
        # Must ABSTAIN and send to ALERT_ANALYST, NEVER auto-contain or lock out!
        self.assertEqual(d11["action"], "ALERT_ANALYST")
        self.assertEqual(d11["rule_fired"], "P3")
        self.assertNotIn("REVOKE", d11["action"])

    def test_protected_identity_rule_p2(self):
        protected_ev = {
            "evidence_id": "ev-test-prot",
            "severity": "CRITICAL",
            "stage_confidence": 0.99,
            "current_stage": "IMPACT",
            "protected_identity": True,
            "indicators": ["NEW_ORIGIN", "AUTH_FAILURE_BURST", "PRIV_ATTR_GRANTED"],
        }
        dec = preview_decision(protected_ev)
        self.assertEqual(dec["action"], "ALERT_ANALYST")
        self.assertEqual(dec["rule_fired"], "P2")


class TestAuditStoreAndTamper(unittest.TestCase):
    """Verify the append-only audit log and live tamper-detection verifier."""

    def setUp(self):
        self.data = load_console_data("stub")
        self.data.audit_store.reset()

    def tearDown(self):
        self.data.audit_store.reset()

    def test_audit_chain_initially_valid(self):
        result = self.data.audit_store.verify()
        self.assertTrue(result.ok, f"Verification failed unexpectedly: {result.message}")

    def test_audit_append(self):
        initial_len = len(self.data.audit_store.entries())
        self.data.audit_store.append({
            "ts": "2026-10-17T12:00:00Z",
            "evidence_id": "ev-test",
            "rule_fired": "ANALYST_OVERRIDE",
            "action": "OVERRIDE_CONFIRM",
            "policy_version": "policy-v0.1.0",
        })
        entries = self.data.audit_store.entries()
        self.assertEqual(len(entries), initial_len + 1)
        self.assertTrue(self.data.audit_store.verify().ok)

    def test_tamper_detection(self):
        # Tamper entry #4
        line_no = self.data.audit_store.tamper(4, "action", "LOG_ONLY")
        self.assertGreater(line_no, 0)

        # Run verifier: it must catch the tampered line
        result = self.data.audit_store.verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_seq, 4)

        # Reset log: must restore integrity
        self.data.audit_store.reset()
        self.assertTrue(self.data.audit_store.verify().ok)


class TestBridgeAndPlaylist(unittest.TestCase):
    """Verify playlist creation and session isolation."""

    def test_pick_sessions(self):
        data = load_console_data("stub")
        attack_sess = pick_sessions(data, "attack")
        self.assertEqual(len(attack_sess), 1)
        self.assertEqual(attack_sess[0].kind, "attack")

        look_sess = pick_sessions(data, "lookalike")
        self.assertEqual(len(look_sess), 1)
        self.assertEqual(look_sess[0].kind, "lookalike")

        both_sess = pick_sessions(data, "both")
        self.assertEqual(len(both_sess), 2)
        self.assertEqual(both_sess[0].kind, "attack")
        self.assertEqual(both_sess[1].kind, "lookalike")

    def test_make_playlist_stepping(self):
        data = load_console_data("stub")
        playlist = make_playlist(data, "attack")
        self.assertEqual(len(playlist), 8)
        # Test compute_view at step 0
        sess, evt, li, ev, dec, rev = compute_view(data, playlist, 0)
        self.assertEqual(sess.session_id, "s1")
        self.assertEqual(evt["event_id"], "e0001")
        self.assertIsNotNone(ev)


class TestSysinfo(unittest.TestCase):
    """Verify host environment inspection."""

    def test_detect_platform(self):
        info = detect_platform()
        self.assertIsInstance(info, PlatformInfo)
        self.assertIsInstance(info.on_linuxone, bool)
        self.assertTrue(len(info.machine) > 0)
        self.assertTrue(len(info.system) > 0)


class TestStreamlitAppTest(unittest.TestCase):
    """Simulate user interactions in the Streamlit console using AppTest."""

    def test_console_headless_interaction(self):
        from streamlit.testing.v1 import AppTest

        at = AppTest.from_file(str(_REPO_ROOT / "app" / "console.py"))
        at.run()
        self.assertFalse(at.exception, f"App crashed on startup: {at.exception}")

        # Test stepping forward
        initial_step = at.session_state["step"]
        self.assertEqual(initial_step, 0)

        for b in at.button:
            if b.label == "Forward":
                b.click()
                break
        at.run()
        self.assertFalse(at.exception)
        self.assertEqual(at.session_state["step"], 1)

        # Test switching scenario to Look-alike
        at.segmented_control(key="scenario").set_value("Look-alike").run()
        self.assertFalse(at.exception)
        self.assertEqual(at.session_state["_scenario"], "lookalike")
        self.assertEqual(at.session_state["step"], 0)

        # Test Tamper and verify button
        at.button(key="do_tamper").click().run()
        self.assertFalse(at.exception)
        self.assertIn("tamper_result", at.session_state)
        line_no, field, val, res = at.session_state["tamper_result"]
        self.assertFalse(res.ok)  # Chain should be broken!

        # Test Reset log button
        at.button(key="reset_log").click().run()
        self.assertFalse(at.exception)
        self.assertNotIn("tamper_result", at.session_state)


if __name__ == "__main__":
    unittest.main()
