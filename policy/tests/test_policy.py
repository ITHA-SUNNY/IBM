"""Tests for the policy agent. Run from the project root:  python3 -m unittest -v

None of these tests needs a model, a dashboard or any other agent's code.
They feed hand-built evidence straight into the policy side.
"""
from __future__ import annotations

import ast
import copy
import itertools
import json
import tempfile
import unittest
from pathlib import Path

from policy_agent import (
    AuditLog,
    EvidenceError,
    EvidenceObject,
    Policy,
    PolicyAgent,
    PolicyConfigError,
)
from policy_agent.engine import DESTRUCTIVE_ACTIONS

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "policy_agent"

# The indicator vocabulary agreed with M3 (rules.json "indicators").
IND = ["new_origin", "off_hours_activity", "mfa_failure_then_success",
       "privilege_change", "sensitive_access", "discovery_sweep"]


def ind(n):
    return IND[:n]


def base(**over):
    data = {
        "actor_id": "jmartinez",
        "session_id": "S-7731",
        "timestamp": "2026-10-17T03:22:30Z",
        "threat_type": "credential_compromise",
        "confidence": 0.93,
        "predicted_next_stage": "exfiltration",
        "indicators": ["new_origin", "off_hours_activity", "privilege_change", "sensitive_access"],
        "resource_tier": "critical",
        "action": "export",
        "is_privileged_actor": True,
    }
    data.update(over)
    return data


def without(data, *keys):
    return {k: v for k, v in data.items() if k not in keys}


def evaluate(policy, **over):
    return policy.evaluate(EvidenceObject.from_dict(base(**over)))


def default_config():
    return json.loads((PKG / "rules.json").read_text(encoding="utf-8"))


class TestDemoScenarios(unittest.TestCase):
    """The cases the live demo is built on."""

    def setUp(self):
        self.policy = Policy.load()

    def test_jmartinez_critical_high_confidence_revokes_session(self):
        d = evaluate(self.policy)
        self.assertEqual((d.severity, d.action, d.rule_id), ("CRITICAL", "REVOKE_SESSION", "P-02"))
        self.assertTrue(d.automated)
        self.assertEqual(d.target, {"actor_id": "jmartinez", "session_id": "S-7731"})

    def test_rkapoor_same_severity_low_confidence_only_alerts(self):
        d = evaluate(self.policy, actor_id="rkapoor", confidence=0.41, indicators=["new_origin"],
                     predicted_next_stage="unknown", action="read")
        self.assertEqual((d.severity, d.action, d.rule_id), ("CRITICAL", "ALERT_ANALYST", "P-03"))
        self.assertFalse(d.automated)

    def test_early_warning_when_threshold_is_approaching(self):
        d = evaluate(self.policy, actor_id="tnguyen", confidence=0.78, predicted_next_stage="lateral_movement",
                     indicators=ind(3), resource_tier="restricted", action="read",
                     is_privileged_actor=False)
        self.assertEqual((d.severity, d.action, d.rule_id), ("HIGH", "EARLY_WARNING", "P-05"))

    def test_very_strong_evidence_locks_credentials(self):
        d = evaluate(self.policy, confidence=0.97, indicators=ind(5))
        self.assertEqual((d.action, d.rule_id), ("LOCK_CREDENTIALS", "P-01"))

    def test_routine_activity_is_log_only(self):
        d = evaluate(self.policy, confidence=0.12, indicators=[], predicted_next_stage="none",
                     resource_tier="internal", action="read", is_privileged_actor=False)
        self.assertEqual((d.action, d.rule_id), ("LOG_ONLY", "DEFAULT"))

    def test_trace_explains_why_revoke_was_not_chosen(self):
        d = evaluate(self.policy, confidence=0.41, indicators=["new_origin"], action="read")
        by_id = {t["rule_id"]: t for t in d.trace}
        self.assertFalse(by_id["P-02"]["matched"])
        self.assertTrue(any("confidence" in f for f in by_id["P-02"]["failed_conditions"]))
        self.assertTrue(any("indicators" in f for f in by_id["P-02"]["failed_conditions"]))
        self.assertTrue(by_id["P-03"]["matched"])


class TestBoundaries(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.load()

    def test_revoke_threshold_is_inclusive_at_0_90(self):
        self.assertEqual(evaluate(self.policy, confidence=0.90, indicators=ind(3),
                                  predicted_next_stage="lateral_movement").action, "REVOKE_SESSION")

    def test_just_below_threshold_does_not_revoke(self):
        d = evaluate(self.policy, confidence=0.8999, indicators=ind(3))
        self.assertEqual(d.action, "ALERT_ANALYST")

    def test_confidence_cannot_make_up_for_too_few_indicators(self):
        d = evaluate(self.policy, confidence=1.0, indicators=ind(2))
        self.assertEqual(d.action, "ALERT_ANALYST")

    def test_lock_needs_a_serious_predicted_stage(self):
        d = evaluate(self.policy, confidence=0.99, indicators=ind(5), predicted_next_stage="privilege_escalation")
        self.assertEqual(d.action, "REVOKE_SESSION")

    def test_high_severity_never_acts_automatically(self):
        d = evaluate(self.policy, confidence=1.0, indicators=ind(5), resource_tier="restricted",
                     action="read", is_privileged_actor=False, predicted_next_stage="exfiltration")
        self.assertEqual(d.severity, "HIGH")
        self.assertFalse(d.automated)

    def test_repeated_indicator_is_counted_once(self):
        ev = EvidenceObject.from_dict(base(indicators=["new_origin", "New_Origin", "new_origin", "privilege_change"]))
        self.assertEqual(ev.indicator_count, 2)
        d = self.policy.evaluate(ev)
        self.assertEqual(d.indicator_count, 2)
        self.assertEqual(d.action, "ALERT_ANALYST")

    def test_unknown_indicators_are_kept_but_not_counted(self):
        d = evaluate(self.policy, confidence=0.99, indicators=["new_origin", "made_up_signal", "another one"])
        self.assertEqual(d.indicator_count, 1)
        self.assertEqual(d.action, "ALERT_ANALYST")
        self.assertTrue(any("not counted" in n and "made_up_signal" in n for n in d.notes))


class TestSeverityIndependence(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.load()

    def test_confidence_and_indicators_never_change_severity(self):
        for tier, action, priv in itertools.product(self.policy.severity_model.tiers,
                                                    self.policy.severity_model.actions, (True, False)):
            seen = set()
            for conf, n in itertools.product((0.0, 0.5, 0.95, 1.0), (0, 2, 5)):
                d = evaluate(self.policy, resource_tier=tier, action=action, is_privileged_actor=priv,
                             confidence=conf, indicators=[f"i{k}" for k in range(n)])
                seen.add((d.severity, d.severity_score))
            self.assertEqual(len(seen), 1, f"severity varied with confidence for {tier}/{action}/{priv}")

    def test_upstream_supplied_severity_is_ignored_and_noted(self):
        d = evaluate(self.policy, severity="LOW", confidence=0.62, indicators=["a", "b"])
        self.assertEqual(d.severity, "CRITICAL")
        self.assertTrue(any("ignored" in n for n in d.notes))

    def test_severity_bands(self):
        sev = self.policy.severity_model.compute
        self.assertEqual(sev("critical", "export", True), ("CRITICAL", 8))
        self.assertEqual(sev("restricted", "read", False), ("HIGH", 4))
        self.assertEqual(sev("internal", "read", False), ("MEDIUM", 3))
        self.assertEqual(sev("public", "login", False), ("LOW", 2))


class TestGuardrailInvariants(unittest.TestCase):
    """Swept over a grid: the default policy can never act on thin evidence."""

    def test_destructive_actions_require_critical_severity_and_strong_evidence(self):
        policy = Policy.load()
        tiers = list(policy.severity_model.tiers)
        actions = list(policy.severity_model.actions)
        checked = 0
        for tier, action, priv, conf, n, stage in itertools.product(
            tiers, actions, (True, False),
            (0.0, 0.5, 0.79, 0.8, 0.89, 0.9, 0.94, 0.95, 1.0),
            range(0, 7),
            ("none", "privilege_escalation", "lateral_movement", "collection_exfil", "impact"),
        ):
            d = evaluate(policy, resource_tier=tier, action=action, is_privileged_actor=priv, confidence=conf,
                         indicators=ind(n), predicted_next_stage=stage)
            checked += 1
            if d.action in DESTRUCTIVE_ACTIONS:
                self.assertEqual(d.severity, "CRITICAL")
                self.assertGreaterEqual(conf, 0.80)
                self.assertGreaterEqual(n, 2)
                self.assertTrue(d.automated)
            else:
                self.assertFalse(d.automated)
        self.assertGreater(checked, 10000)

    def test_benign_current_stage_never_acts_automatically(self):
        """A confident BENIGN call is confidence in benign, never grounds to revoke or lock."""
        policy = Policy.load()
        for tier, action, conf, stage in itertools.product(
            policy.severity_model.tiers, policy.severity_model.actions, (0.9, 0.97, 1.0),
            ("collection_exfil", "impact", "privilege_escalation"),
        ):
            for benign in ("benign", "BENIGN", "none"):
                d = evaluate(policy, threat_type=benign, resource_tier=tier, action=action, confidence=conf,
                             indicators=ind(6), predicted_next_stage=stage, is_privileged_actor=True)
                self.assertNotIn(d.action, DESTRUCTIVE_ACTIONS, (benign, tier, action))

    def test_decisions_are_deterministic(self):
        policy = Policy.load()
        first = evaluate(policy).to_dict()
        for _ in range(5):
            self.assertEqual(evaluate(policy).to_dict(), first)


class TestEvidenceValidation(unittest.TestCase):
    def check_rejected(self, data, fragment):
        with self.assertRaises(EvidenceError) as ctx:
            EvidenceObject.from_dict(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_missing_fields_are_all_reported(self):
        self.check_rejected(without(base(), "is_privileged_actor", "resource_tier"), "is_privileged_actor")

    def test_confidence_must_be_a_real_probability(self):
        for bad in (1.5, -0.1, float("nan"), float("inf"), "0.9", None, True):
            self.check_rejected(base(confidence=bad), "confidence")

    def test_confidence_bounds_are_accepted(self):
        for ok in (0, 0.0, 1, 1.0):
            self.assertEqual(EvidenceObject.from_dict(base(confidence=ok)).confidence, float(ok))

    def test_privileged_flag_must_be_boolean(self):
        self.check_rejected(base(is_privileged_actor="yes"), "is_privileged_actor")

    def test_indicators_must_be_strings(self):
        self.check_rejected(base(indicators="odd login"), "indicators")
        self.check_rejected(base(indicators=["ok", 5]), "indicators")

    def test_non_object_evidence_rejected(self):
        for bad in ("text", 5, None, [1, 2]):
            self.check_rejected(bad, "JSON object")

    def test_timestamp_forms(self):
        self.assertTrue(EvidenceObject.from_dict(base(timestamp="2026-10-17T03:22:30Z")).timestamp.endswith("+00:00"))
        self.assertTrue(EvidenceObject.from_dict(base(timestamp="2026-10-17T03:22:30")).timestamp.endswith("+00:00"))
        self.assertTrue(EvidenceObject.from_dict(base(timestamp="2026-10-17T08:52:30+05:30")).timestamp.startswith("2026-10-17T03:22:30"))
        self.check_rejected(base(timestamp="yesterday"), "timestamp")

    def test_tokens_are_normalised(self):
        ev = EvidenceObject.from_dict(base(predicted_next_stage="Lateral Movement", resource_tier=" Critical ",
                                           threat_type="Credential-Compromise"))
        self.assertEqual((ev.predicted_next_stage, ev.resource_tier, ev.threat_type),
                         ("lateral_movement", "critical", "credential_compromise"))

    def test_extra_keys_are_kept_but_do_not_affect_the_decision(self):
        policy = Policy.load()
        plain = policy.evaluate(EvidenceObject.from_dict(base()))
        extra = EvidenceObject.from_dict(base(model_name="hmm-v1", window_start="03:14"))
        self.assertEqual(extra.extras, {"model_name": "hmm-v1", "window_start": "03:14"})
        self.assertEqual(policy.evaluate(extra).action, plain.action)


class TestFailSafe(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agent = PolicyAgent(audit_path=str(Path(self._tmp.name) / "audit.jsonl"))

    def test_malformed_evidence_alerts_and_never_acts(self):
        d = self.agent.process(base(confidence=1.7))
        self.assertEqual((d.action, d.rule_id, d.automated), ("ALERT_ANALYST", "FAILSAFE", False))
        self.assertEqual(d.target["actor_id"], "jmartinez")

    def test_unknown_tier_or_action_fails_safe(self):
        for over in ({"resource_tier": "top_secret"}, {"action": "teleport"}):
            d = self.agent.process(base(**over))
            self.assertEqual((d.rule_id, d.automated), ("FAILSAFE", False))

    def test_garbage_input_does_not_raise(self):
        for garbage in (None, "not json", 42, [1, 2], {}, {1: "a", "b": 2}):
            self.assertEqual(self.agent.process(garbage).rule_id, "FAILSAFE")

    def test_failsafe_decisions_are_logged_and_chain_still_verifies(self):
        self.agent.process(base())
        self.agent.process(base(confidence=9))
        entries = self.agent.audit.entries()
        self.assertEqual([e["status"] for e in entries], ["ok", "failsafe"])
        self.assertTrue(entries[1]["validation_errors"])
        self.assertTrue(self.agent.audit.verify().ok)


class TestConfigValidation(unittest.TestCase):
    def mutate(self, fn):
        cfg = copy.deepcopy(default_config())
        fn(cfg)
        return cfg

    def assertConfigRejected(self, fn, fragment):
        with self.assertRaises(PolicyConfigError) as ctx:
            Policy(self.mutate(fn))
        self.assertIn(fragment, str(ctx.exception))

    def test_default_config_loads(self):
        self.assertEqual(Policy.load().version, "1.1.0")

    def test_destructive_rule_must_exclude_benign(self):
        self.assertConfigRejected(lambda c: c["rules"][1]["when"].pop("threat_type_not_in"), "benign")
        self.assertConfigRejected(lambda c: c["rules"][0]["when"].update({"threat_type_not_in": ["none_x"]}),
                                  "benign")

    def test_bad_indicator_vocabulary_rejected(self):
        self.assertConfigRejected(lambda c: c.update({"indicators": []}), "indicators")

    def test_thresholds_are_read_from_config(self):
        cfg = self.mutate(lambda c: c["rules"][4]["when"].update({"min_next_confidence": 0.95}))
        ev = base(confidence=0.5, next_confidence=0.9, predicted_next_stage="lateral_movement",
                  resource_tier="internal", action="read", is_privileged_actor=False)
        self.assertEqual(Policy.load().evaluate(EvidenceObject.from_dict(ev)).action, "EARLY_WARNING")
        self.assertEqual(Policy(cfg).evaluate(EvidenceObject.from_dict(ev)).action, "LOG_ONLY")

    def test_misspelled_condition_is_rejected_not_silently_ignored(self):
        self.assertConfigRejected(lambda c: c["rules"][1]["when"].update({"min_confidnce": 0.5}), "unknown condition")

    def test_destructive_rule_must_require_indicators(self):
        self.assertConfigRejected(lambda c: c["rules"][1]["when"].pop("min_indicators"), "min_indicators")

    def test_destructive_rule_cannot_go_below_confidence_floor(self):
        self.assertConfigRejected(lambda c: c["rules"][1]["when"].update({"min_confidence": 0.5}), "min_confidence")

    def test_destructive_rule_must_name_severity(self):
        self.assertConfigRejected(lambda c: c["rules"][1]["when"].pop("severity_in"), "severity_in")

    def test_default_cannot_be_destructive(self):
        self.assertConfigRejected(lambda c: c["default"].update({"action": "REVOKE_SESSION"}), "destructive")

    def test_empty_condition_is_rejected(self):
        self.assertConfigRejected(lambda c: c["rules"][4].update({"when": {}}), "non-empty object")

    def test_duplicate_rule_ids_rejected(self):
        self.assertConfigRejected(lambda c: c["rules"][1].update({"id": "P-01"}), "duplicated")

    def test_unknown_action_rejected(self):
        self.assertConfigRejected(lambda c: c["rules"][0].update({"action": "DELETE_USER"}), "unknown action")

    def test_bad_severity_bands_rejected(self):
        self.assertConfigRejected(lambda c: c["severity"]["bands"].update({"HIGH": 9}), "rise")

    def test_unreadable_file_reports_cleanly(self):
        with self.assertRaises(PolicyConfigError):
            Policy.load(str(ROOT / "no_such_rules.json"))

    def test_alternate_config_changes_behaviour(self):
        cfg = self.mutate(lambda c: c["rules"][1]["when"].update({"min_confidence": 0.99}))
        d = Policy(cfg).evaluate(EvidenceObject.from_dict(base(confidence=0.93)))
        self.assertEqual(d.action, "ALERT_ANALYST")


class TestAudit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "audit.jsonl"
        self.agent = PolicyAgent(audit_path=str(self.path))
        for actor in ("jmartinez", "rkapoor", "jmartinez"):
            self.agent.process(base(actor_id=actor))

    def lines(self):
        return self.path.read_text(encoding="utf-8").splitlines()

    def write(self, lines):
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_clean_log_verifies(self):
        result = self.agent.audit.verify()
        self.assertTrue(result.ok)
        self.assertEqual(result.entries, 3)
        self.assertEqual(result.head_hash, self.agent.audit.head_hash())

    def test_every_entry_carries_the_evidence_and_the_rule_that_fired(self):
        entry = self.agent.audit.entries()[0]
        self.assertEqual(entry["decision"]["rule_id"], "P-02")
        self.assertEqual(entry["evidence"]["actor_id"], "jmartinez")
        self.assertEqual(len(entry["evidence_hash"]), 64)
        self.assertEqual(entry["policy_version"], "1.1.0")
        self.assertTrue(entry["decision"]["trace"])

    def test_entries_follow_the_shared_audit_contract(self):
        """seq, ts, evidence_id, rule_fired, action, policy_version, prev_hash, entry_hash at top level,
        entry_hash = SHA-256(prev_hash + canonical_json(entry without entry_hash))."""
        import hashlib
        self.agent.process(base(evidence_id="ev-42"))
        prev = "0" * 64
        for entry in self.agent.audit.entries():
            for key in ("seq", "ts", "evidence_id", "rule_fired", "action", "policy_version",
                        "prev_hash", "entry_hash"):
                self.assertIn(key, entry)
            self.assertRegex(entry["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
            self.assertEqual(entry["rule_fired"], entry["decision"]["rule_id"])
            self.assertEqual(entry["action"], entry["decision"]["action"])
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            self.assertEqual(entry["entry_hash"], hashlib.sha256((prev + canon).encode("utf-8")).hexdigest())
            prev = entry["entry_hash"]
        self.assertEqual(self.agent.audit.entries()[-1]["evidence_id"], "ev-42")

    def test_verify_reports_the_broken_line_and_seq(self):
        lines = self.lines()
        entry = json.loads(lines[2])
        entry["action"] = "LOG_ONLY"
        lines[2] = json.dumps(entry)
        self.write(lines)
        result = self.agent.audit.verify()
        self.assertEqual((result.ok, result.line_no, result.broken_seq), (False, 3, 3))

    def test_repo_verifier_script_uses_the_same_chain(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("audit_verify", ROOT.parent / "audit" / "verify.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(module.verify_log(str(self.path))["ok"])
        lines = self.lines()
        del lines[0]
        self.write(lines)
        out = module.verify_log(str(self.path))
        self.assertFalse(out["ok"])
        self.assertEqual(out["line_no"], 1)

    def test_edited_entry_is_detected(self):
        lines = self.lines()
        entry = json.loads(lines[1])
        entry["decision"]["action"] = "LOG_ONLY"
        lines[1] = json.dumps(entry)
        self.write(lines)
        result = self.agent.audit.verify()
        self.assertFalse(result.ok)
        self.assertIn("line 2", result.problem)
        self.assertEqual(result.entries, 1)

    def test_deleted_entry_is_detected(self):
        lines = self.lines()
        del lines[1]
        self.write(lines)
        result = self.agent.audit.verify()
        self.assertFalse(result.ok)
        self.assertIn("line 2", result.problem)

    def test_reordered_entries_are_detected(self):
        lines = self.lines()
        lines[0], lines[1] = lines[1], lines[0]
        self.write(lines)
        self.assertFalse(self.agent.audit.verify().ok)

    def test_garbage_line_is_detected(self):
        lines = self.lines()
        lines.insert(2, "this is not json")
        self.write(lines)
        self.assertFalse(self.agent.audit.verify().ok)

    def test_new_agent_continues_the_same_chain(self):
        PolicyAgent(audit_path=str(self.path)).process(base(actor_id="dpatel"))
        result = AuditLog(str(self.path)).verify()
        self.assertTrue(result.ok)
        self.assertEqual(result.entries, 4)

    def test_replay_filters_by_actor_and_session(self):
        self.assertEqual(len(self.agent.audit.replay(actor_id="jmartinez")), 2)
        self.assertEqual(len(self.agent.audit.replay(actor_id="rkapoor")), 1)
        self.assertEqual(len(self.agent.audit.replay(actor_id="jmartinez", session_id="nope")), 0)

    def test_empty_log_verifies(self):
        self.assertTrue(AuditLog(str(Path(self._tmp.name) / "fresh.jsonl")).verify().ok)


def m2_event(event_id, event_type, sensitivity, outcome="SUCCESS", ts="2026-10-17T02:03:19Z"):
    """One events.csv row in the M2 v3 vocabulary."""
    return {"event_id": event_id, "timestamp": ts, "system_id": "SYS1", "actor_id": "U_1ec5537a4af5",
            "session_id": "demo-00002", "event_type": event_type, "outcome": outcome, "resource": "RACF_DB",
            "sensitivity": sensitivity, "origin": "NEW_NET", "off_hours": "1"}


# demo-00002 (attack_v1) from data/demo_stream.csv, up to the privilege escalation.
ATTACK_EVENTS = [
    m2_event("e000", "LOGON", "LOW"), m2_event("e001", "MFA", "LOW", "FAILURE"),
    m2_event("e002", "MFA", "LOW"), m2_event("e003", "RACF_LISTUSER", "MEDIUM"),
    m2_event("e005", "DATASET_LIST", "MEDIUM"), m2_event("e006", "ALTUSER_SPECIAL", "HIGH"),
]


def m3_evidence(**over):
    """The evidence.json shape M3 sends after every event."""
    data = {
        "evidence_id": "ev-demo-00002-6", "actor": "U_1ec5537a4af5", "session_id": "demo-00002",
        "current_stage": "PRIVILEGE_ESCALATION", "stage_confidence": 0.94,
        "next_stage": "COLLECTION_EXFIL", "next_confidence": 0.88, "severity": "HIGH",
        "indicators": ["new_origin", "off_hours_activity", "mfa_failure_then_success", "privilege_change"],
        "top_events": ["e006", "e005", "e003", "e002", "e001"], "model_version": "m3-v1",
    }
    data.update(over)
    return data


class TestModelContract(unittest.TestCase):
    """M3 evidence.json + M2 events.csv rows go straight in via process_model_evidence."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.agent = PolicyAgent(audit_path=str(Path(self._tmp.name) / "audit.jsonl"))

    def test_m2_vocabulary_has_severity_weights(self):
        sev = self.agent.policy.severity_model.compute
        self.assertEqual(sev("high", "altuser_special", False), ("CRITICAL", 6))
        self.assertEqual(sev("high", "dataset_copy", False), ("CRITICAL", 6))
        self.assertEqual(sev("high", "dataset_read", False), ("HIGH", 4))
        self.assertEqual(sev("medium", "dataset_list", False), ("MEDIUM", 3))
        self.assertEqual(sev("low", "logon", False), ("LOW", 2))

    def test_attack_privilege_escalation_revokes(self):
        d = self.agent.process_model_evidence(m3_evidence(), ATTACK_EVENTS)
        self.assertEqual((d.severity, d.action, d.rule_id), ("CRITICAL", "REVOKE_SESSION", "P-02"))
        self.assertEqual((d.threat_type, d.predicted_next_stage), ("privilege_escalation", "collection_exfil"))
        self.assertEqual(d.target, {"actor_id": "U_1ec5537a4af5", "session_id": "demo-00002"})
        self.assertTrue(any("ALTUSER_SPECIAL" in n.upper() or "altuser_special" in n for n in d.notes))

    def test_very_strong_attack_evidence_locks(self):
        d = self.agent.process_model_evidence(
            m3_evidence(stage_confidence=0.97, indicators=ind(5)), ATTACK_EVENTS)
        self.assertEqual((d.action, d.rule_id), ("LOCK_CREDENTIALS", "P-01"))

    def test_confident_benign_lookalike_is_never_contained(self):
        """Admin look-alike: same ALTUSER_SPECIAL on HIGH data, model says BENIGN at 0.97."""
        d = self.agent.process_model_evidence(
            m3_evidence(current_stage="BENIGN", stage_confidence=0.97, next_stage="BENIGN",
                        next_confidence=0.9, indicators=["off_hours_activity", "privilege_change", "sensitive_access"]),
            ATTACK_EVENTS)
        self.assertEqual(d.severity, "CRITICAL")
        self.assertEqual((d.action, d.rule_id, d.automated), ("ALERT_ANALYST", "P-03", False))

    def test_early_warning_uses_next_confidence(self):
        early = [m2_event("e000", "LOGON", "LOW"), m2_event("e003", "RACF_LISTUSER", "MEDIUM")]
        warn = self.agent.process_model_evidence(
            m3_evidence(current_stage="DISCOVERY", stage_confidence=0.6, next_stage="PRIVILEGE_ESCALATION",
                        next_confidence=0.81, indicators=ind(2)), early)
        self.assertEqual((warn.action, warn.rule_id), ("EARLY_WARNING", "P-05"))
        quiet = self.agent.process_model_evidence(
            m3_evidence(current_stage="DISCOVERY", stage_confidence=0.95, next_stage="PRIVILEGE_ESCALATION",
                        next_confidence=0.6, indicators=ind(2)), early)
        self.assertEqual(quiet.action, "LOG_ONLY")

    def test_lateral_movement_forecast_warns(self):
        d = self.agent.process_model_evidence(
            m3_evidence(current_stage="PRIVILEGE_ESCALATION", stage_confidence=0.7,
                        next_stage="LATERAL_MOVEMENT", next_confidence=0.8, indicators=ind(2)),
            [m2_event("e000", "LOGON", "LOW")])
        self.assertEqual((d.action, d.rule_id), ("EARLY_WARNING", "P-05"))

    def test_stage_names_and_aliases_agree(self):
        for name in ("COLLECTION_EXFIL", "collection exfil", "exfiltration"):
            d = self.agent.process_model_evidence(
                m3_evidence(stage_confidence=0.97, next_stage=name, indicators=ind(5)), ATTACK_EVENTS)
            self.assertEqual(d.rule_id, "P-01", name)

    def test_m3_extras_are_accepted_and_audited(self):
        self.agent.process_model_evidence(m3_evidence(), ATTACK_EVENTS)
        entry = self.agent.audit.entries()[-1]
        self.assertEqual(entry["evidence_id"], "ev-demo-00002-6")
        extras = entry["evidence"]["extras"]
        self.assertEqual(extras["top_events"], ["e006", "e005", "e003", "e002", "e001"])
        self.assertEqual(extras["severity"], "HIGH")
        self.assertEqual(entry["evidence"]["next_confidence"], 0.88)

    def test_indicator_objects_are_accepted(self):
        objs = [{"id": i, "source": "SMF80", "event_ids": ["e001"]} for i in ind(3)]
        d = self.agent.process_model_evidence(m3_evidence(indicators=objs), ATTACK_EVENTS)
        self.assertEqual(d.indicator_count, 3)

    def test_unknown_event_vocabulary_fails_safe(self):
        d = self.agent.process_model_evidence(
            m3_evidence(), ATTACK_EVENTS + [m2_event("e099", "WRITE_DATASET", "HIGH")])
        self.assertEqual((d.rule_id, d.automated), ("FAILSAFE", False))
        self.assertEqual(d.target["actor_id"], "U_1ec5537a4af5")

    def test_no_events_fails_safe(self):
        self.assertEqual(self.agent.process_model_evidence(m3_evidence(), []).rule_id, "FAILSAFE")

    def test_failed_privilege_probe_does_not_set_severity(self):
        events = [m2_event("e000", "LOGON", "LOW"), m2_event("e001", "ALTUSER_SPECIAL", "HIGH", "FAILURE"),
                  m2_event("e002", "DATASET_LIST", "MEDIUM")]
        d = self.agent.process_model_evidence(m3_evidence(), events)
        self.assertEqual(d.severity, "MEDIUM")
        self.assertFalse(d.automated)

    def test_missing_model_fields_fail_safe(self):
        bad = m3_evidence()
        del bad["stage_confidence"]
        self.assertEqual(self.agent.process_model_evidence(bad, ATTACK_EVENTS).rule_id, "FAILSAFE")
        self.assertTrue(self.agent.audit.verify().ok)


class TestArchitecture(unittest.TestCase):
    """The pitch claim, enforced: the policy side contains no ML and no third-party code."""

    ALLOWED = {
        "__future__", "argparse", "dataclasses", "datetime", "hashlib", "json",
        "math", "pathlib", "sys", "threading", "typing",
    }

    def test_policy_package_imports_only_the_standard_library(self):
        offenders = []
        for source in sorted(PKG.glob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                offenders += [f"{source.name}: {n}" for n in names if n not in self.ALLOWED]
        self.assertEqual(offenders, [], "policy_agent must stay stdlib-only and ML-free")


if __name__ == "__main__":
    unittest.main()
