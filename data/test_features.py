import json
import unittest
from features import feature_rows


def event(i,session="a",actor="U_a",et="LOGON",op="AUTHENTICATE",outcome="SUCCESS"):
    return dict(event_id=str(i),timestamp=f"2026-10-17T02:00:{i:02d}Z",actor_id=actor,session_id=session,event_type=et,operation=op,outcome=outcome,sensitivity="HIGH",resource="DATA",origin="KNOWN_NET",off_hours="1")


class FeatureTests(unittest.TestCase):
    def test_mfa_requires_ordered_success_and_session_isolation(self):
        rows=[event(1,et="MFA",op="CHALLENGE",outcome="FAILURE"),event(2,session="b",et="MFA",op="CHALLENGE"),event(3,et="MFA",op="CHALLENGE")]
        features=feature_rows(rows)
        self.assertEqual([f["mfa_failure_then_success"] for f in features],[0,0,1])
    def test_future_events_do_not_change_past_features(self):
        rows=[event(1),event(2,et="ALTUSER_SPECIAL",op="GRANT_SPECIAL")]
        self.assertEqual(feature_rows(rows[:1]),feature_rows(rows)[:1])
    def test_ground_truth_is_ignored(self):
        row=event(1);plain=feature_rows([row]);row.update(stage_label="IMPACT",scenario_id="attack")
        self.assertEqual(plain,feature_rows([row]))
    def test_failed_privilege_and_listing_are_not_sensitive_access(self):
        rows=[event(1,et="ALTUSER_SPECIAL",op="GRANT_SPECIAL",outcome="FAILURE"),event(2,et="DATASET_LIST",op="LIST")]
        last=feature_rows(rows)[-1]
        self.assertEqual(last["privilege_change_count"],0);self.assertEqual(last["sensitive_access_count"],0)
    def test_window_evicts_old_failures(self):
        rows=[event(1,outcome="FAILURE"),event(2),event(3)]
        self.assertEqual(feature_rows(rows,window=2)[-1]["failure_count"],0)
    def test_zero_flag_remains_false(self):
        row=event(1);row["off_hours"]="0"
        self.assertNotIn("off_hours_activity",json.loads(feature_rows([row])[0]["indicators"]))


if __name__=="__main__":unittest.main()
