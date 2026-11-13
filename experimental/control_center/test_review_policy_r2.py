"""Deterministic R2 review-policy contract tests, synthetic data only."""
import unittest

from review_policy_r2 import advise_review, memory_and_execution, reject_once_capability


class ReviewPolicyTests(unittest.TestCase):
    def test_memory_outcomes_do_not_stop_authorized_work(self):
        for outcome in ("ADMITTED", "REVIEW_REQUIRED", "REJECTED", "DEFERRED", "NO_RESPONSE"):
            with self.subTest(outcome=outcome):
                response = memory_and_execution(outcome, execution_authorized=True)
                self.assertTrue(response["project_may_continue"])
                self.assertEqual(response["memory_admitted"], outcome == "ADMITTED")

    def test_independent_execution_gates_still_apply(self):
        for gate in ("exclusive_inference_lease", "deployment", "credential_access", "safety"):
            response = memory_and_execution(
                "DEFERRED", execution_authorized=True, independent_gates=[gate]
            )
            self.assertFalse(response["project_may_continue"])

    def test_unapproved_execution_is_never_granted(self):
        for outcome in ("ADMITTED", "REVIEW_REQUIRED", "REJECTED"):
            self.assertFalse(
                memory_and_execution(outcome, execution_authorized=False)["project_may_continue"]
            )

    def test_approval_pattern_proposes_review_not_permission(self):
        entry = {
            "subject": "SYNTHETIC_PROJECT",
            "domain": "BUILD_PROJECT",
            "event_class": "OBSERVATION",
            "reason": "UNCERTAIN",
        }
        response = advise_review(entry, {"approved": [entry] * 3, "rejected": []})
        self.assertEqual(response["suggestion"], "propose_human_classifier_review")
        self.assertFalse(response["auto_admit"])
        self.assertFalse(response["auto_declassify"])
        self.assertFalse(response["create_persistent_rule"])

    def test_protected_reason_never_relaxed_by_repetition(self):
        entry = {
            "subject": "SYNTHETIC_PROJECT",
            "domain": "BUILD_PROJECT",
            "event_class": "OBSERVATION",
            "reason": "PRIVACY_CLASS_REVIEW_REQUIRED",
        }
        response = advise_review(entry, {"approved": [entry] * 100})
        self.assertEqual(response["suggestion"], "retain_per_item_owner_review")
        self.assertTrue(response["protected_reason"])

    def test_reject_once_is_not_mislabeled_production_ready(self):
        result = reject_once_capability()
        self.assertFalse(result["available_in_production"])
        self.assertTrue(result["existing_broad_reject_is_not_equivalent"])


if __name__ == "__main__":
    unittest.main()
