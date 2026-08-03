from dataclasses import replace
from datetime import datetime, timezone
import math
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.domain import FeatureVector, MailObservation
from shielddome_endpoint.feature_pipeline import (
    FEATURE_ATTACHMENT_MAX_ITEMS,
    FEATURE_AUTHENTICATION_MAX_ITEMS,
    FEATURE_TEXT_MAX_CHARACTERS,
    FEATURE_URL_MAX_ITEMS,
    FeaturePipeline,
)
from shielddome_endpoint.rule_evaluator import LocalRuleEvaluator


def make_observation(**changes) -> MailObservation:
    values = {
        "source_kind": "browser",
        "source_message_id": "synthetic-rule-message",
        "subject": "Routine notice",
        "sender": "sender@corp.test",
        "reply_to": "sender@corp.test",
        "recipient_summary": ("current-user",),
        "sanitized_body_text": "Use the normal company process.",
        "authentication_observations": (
            ("spf", "pass"),
            ("dkim", "pass"),
            ("dmarc", "pass"),
        ),
        "normalized_links": (),
        "attachment_metadata": (),
        "language_hint": "en",
        "observed_at": datetime(2026, 7, 31, tzinfo=timezone.utc),
    }
    values.update(changes)
    return MailObservation(**values)


def make_vector(**observation_changes) -> FeatureVector:
    return FeaturePipeline().transform(make_observation(**observation_changes))


class FeatureVectorBoundaryTests(unittest.TestCase):
    def test_pipeline_vector_is_accepted_without_mutation(self):
        vector = make_vector()

        result = LocalRuleEvaluator().evaluate(vector)

        self.assertEqual(result, ())
        self.assertIsInstance(result, tuple)
        self.assertEqual(vector, make_vector())

    def test_incompatible_schema_is_rejected_with_stable_code(self):
        vector = replace(make_vector(), schema_version="future")

        with self.assertRaisesRegex(
            ValueError,
            "^incompatible_feature_schema$",
        ):
            LocalRuleEvaluator().evaluate(vector)

    def test_duplicate_missing_and_unknown_numeric_names_are_rejected(self):
        vector = make_vector()
        cases = (
            replace(
                vector,
                numeric_features=vector.numeric_features
                + (vector.numeric_features[0],),
            ),
            replace(vector, numeric_features=vector.numeric_features[1:]),
            replace(
                vector,
                numeric_features=vector.numeric_features[:-1]
                + (("unknown_numeric", 0.0),),
            ),
        )

        for invalid in cases:
            with self.subTest(invalid=invalid.numeric_features):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_numeric_features$",
                ):
                    LocalRuleEvaluator().evaluate(invalid)

    def test_complete_unique_names_are_read_independently_of_pair_order(self):
        vector = make_vector(
            reply_to="other@outside.test",
            sanitized_body_text="password urgent",
        )
        reordered = replace(
            vector,
            numeric_features=tuple(reversed(vector.numeric_features)),
            categorical_features=tuple(reversed(vector.categorical_features)),
        )

        self.assertEqual(
            LocalRuleEvaluator().evaluate(reordered),
            LocalRuleEvaluator().evaluate(vector),
        )

    def test_duplicate_missing_and_unknown_categorical_names_are_rejected(self):
        vector = make_vector()
        cases = (
            replace(
                vector,
                categorical_features=vector.categorical_features
                + (vector.categorical_features[0],),
            ),
            replace(
                vector,
                categorical_features=vector.categorical_features[1:],
            ),
            replace(
                vector,
                categorical_features=vector.categorical_features[:-1]
                + (("unknown_categorical", "value"),),
            ),
        )

        for invalid in cases:
            with self.subTest(invalid=invalid.categorical_features):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_categorical_features$",
                ):
                    LocalRuleEvaluator().evaluate(invalid)

    def test_non_finite_boolean_and_negative_numeric_values_are_rejected(self):
        vector = make_vector()
        cases = (math.nan, math.inf, -math.inf, True, -1.0)

        for value in cases:
            with self.subTest(value=value):
                invalid = replace(
                    vector,
                    numeric_features=(
                        (vector.numeric_features[0][0], value),
                    )
                    + vector.numeric_features[1:],
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_numeric_features$",
                ):
                    LocalRuleEvaluator().evaluate(invalid)


class StructuredRuleTests(unittest.TestCase):
    def test_authentication_failures_are_conservative_and_missing_is_not_strong(self):
        rules = LocalRuleEvaluator().evaluate(
            make_vector(
                authentication_observations=(
                    ("spf", "fail"),
                    ("dkim", "fail"),
                    ("dmarc", "fail"),
                ),
            )
        )

        self.assertEqual(
            tuple(rule.rule_id for rule in rules),
            (
                "auth_dmarc_fail",
                "auth_spf_fail",
                "auth_dkim_fail",
                "auth_multiple_failures",
            ),
        )
        self.assertEqual(
            tuple(rule.score_contribution for rule in rules),
            (24, 14, 14, 20),
        )
        self.assertFalse(any(rule.strong_evidence for rule in rules))

        softfail = LocalRuleEvaluator().evaluate(
            make_vector(
                authentication_observations=(
                    ("spf", "softfail"),
                    ("dkim", "pass"),
                    ("dmarc", "pass"),
                ),
            )
        )
        missing = LocalRuleEvaluator().evaluate(
            make_vector(authentication_observations=())
        )

        self.assertEqual(tuple(rule.rule_id for rule in softfail), ("auth_spf_softfail",))
        self.assertEqual(softfail[0].score_contribution, 8)
        self.assertEqual(missing, ())

    def test_reply_to_domain_mismatch_is_not_strong(self):
        rules = LocalRuleEvaluator().evaluate(
            make_vector(reply_to="other@outside.test")
        )

        self.assertEqual(tuple(rule.rule_id for rule in rules), ("sender_reply_mismatch",))
        self.assertEqual(rules[0].score_contribution, 12)
        self.assertFalse(rules[0].strong_evidence)

    def test_structural_link_rules_use_bounded_feature_counts(self):
        links = (
            "http://192.0.2.10:8080/login",
            "https://xn--fsqu00a.test/path",
            "https://例子.test/path",
        ) + tuple(
            f"https://safe-{index}.example.test/path" for index in range(18)
        )

        rules = LocalRuleEvaluator().evaluate(make_vector(normalized_links=links))

        self.assertEqual(
            tuple(rule.rule_id for rule in rules),
            (
                "link_ip_literal",
                "link_suspicious_port",
                "link_punycode_domain",
                "link_unicode_domain",
                "link_count_high",
            ),
        )
        self.assertFalse(any(rule.strong_evidence for rule in rules))

    def test_attachment_rules_use_metadata_only_and_dangerous_extension_is_strong(self):
        rules = LocalRuleEvaluator().evaluate(
            make_vector(
                attachment_metadata=(("name", "synthetic.pdf.exe"),),
            )
        )

        self.assertEqual(
            tuple(rule.rule_id for rule in rules),
            (
                "attachment_dangerous_extension",
                "attachment_double_extension",
            ),
        )
        self.assertTrue(rules[0].strong_evidence)
        self.assertEqual(rules[0].score_contribution, 35)
        self.assertFalse(rules[1].strong_evidence)


class IntentCombinationRuleTests(unittest.TestCase):
    def test_single_intent_signal_does_not_create_rule_or_strong_evidence(self):
        for body in ("password", "payment", "urgent", "CEO"):
            with self.subTest(body=body):
                rules = LocalRuleEvaluator().evaluate(
                    make_vector(sanitized_body_text=body)
                )

                self.assertEqual(rules, ())

    def test_intent_pairs_create_only_non_strong_combination_rules(self):
        cases = (
            ("password urgent", "intent_credential_urgency"),
            ("payment urgent", "intent_payment_urgency"),
            ("CEO password", "intent_impersonation_credential"),
            ("CEO payment", "intent_impersonation_payment"),
        )

        for body, expected_rule_id in cases:
            with self.subTest(body=body):
                rules = LocalRuleEvaluator().evaluate(
                    make_vector(sanitized_body_text=body)
                )

                self.assertEqual(
                    tuple(rule.rule_id for rule in rules),
                    (expected_rule_id,),
                )
                self.assertFalse(rules[0].strong_evidence)

    def test_ip_literal_with_credential_intent_is_strong(self):
        rules = LocalRuleEvaluator().evaluate(
            make_vector(
                sanitized_body_text="Verify password",
                normalized_links=("http://192.0.2.10/login",),
            )
        )

        self.assertEqual(
            tuple(rule.rule_id for rule in rules),
            ("link_ip_literal", "link_ip_credential"),
        )
        self.assertFalse(rules[0].strong_evidence)
        self.assertTrue(rules[1].strong_evidence)
        self.assertEqual(rules[1].score_contribution, 35)

    def test_multiple_authentication_failures_with_impersonation_is_strong(self):
        rules = LocalRuleEvaluator().evaluate(
            make_vector(
                sanitized_body_text="CEO request",
                authentication_observations=(
                    ("spf", "fail"),
                    ("dkim", "fail"),
                    ("dmarc", "pass"),
                ),
            )
        )

        self.assertEqual(
            tuple(rule.rule_id for rule in rules),
            (
                "auth_spf_fail",
                "auth_dkim_fail",
                "auth_multiple_failures",
                "auth_failures_impersonation",
            ),
        )
        self.assertTrue(rules[-1].strong_evidence)
        self.assertEqual(rules[-1].score_contribution, 35)


class RuleStabilityAndResourceTests(unittest.TestCase):
    def test_same_vector_has_stable_order_and_unique_codes(self):
        vector = make_vector(
            sender="sender@corp.test",
            reply_to="other@outside.test",
            sanitized_body_text="CEO password payment urgent",
            authentication_observations=(
                ("spf", "fail"),
                ("dkim", "fail"),
                ("dmarc", "fail"),
            ),
            normalized_links=(
                "http://192.0.2.10:8080/login",
                "https://xn--fsqu00a.test/path",
                "https://例子.test/path",
            ),
            attachment_metadata=(("name", "synthetic.pdf.exe"),),
        )

        first = LocalRuleEvaluator().evaluate(vector)
        second = LocalRuleEvaluator().evaluate(vector)
        rule_ids = tuple(rule.rule_id for rule in first)
        evidence_codes = tuple(rule.evidence_code for rule in first)

        self.assertEqual(first, second)
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertEqual(len(evidence_codes), len(set(evidence_codes)))

    def test_observation_overflow_cannot_expand_rule_evaluation_input(self):
        bounded = make_observation(
            subject="",
            sanitized_body_text="a" * FEATURE_TEXT_MAX_CHARACTERS,
            authentication_observations=tuple(
                (f"x-auth-{index}", "pass")
                for index in range(FEATURE_AUTHENTICATION_MAX_ITEMS)
            ),
            normalized_links=tuple(
                f"https://safe-{index}.example.test/path"
                for index in range(FEATURE_URL_MAX_ITEMS)
            ),
            attachment_metadata=tuple(
                ("name", f"notice-{index}.txt")
                for index in range(FEATURE_ATTACHMENT_MAX_ITEMS)
            ),
        )
        overflow = replace(
            bounded,
            sanitized_body_text=bounded.sanitized_body_text
            + " CEO password urgent",
            authentication_observations=bounded.authentication_observations
            + (("spf", "fail"), ("dkim", "fail"), ("dmarc", "fail")),
            normalized_links=bounded.normalized_links
            + ("http://192.0.2.10:8080/login",),
            attachment_metadata=bounded.attachment_metadata
            + (("name", "private.pdf.exe"),),
        )

        bounded_vector = FeaturePipeline().transform(bounded)
        overflow_vector = FeaturePipeline().transform(overflow)
        bounded_rules = LocalRuleEvaluator().evaluate(bounded_vector)
        overflow_rules = LocalRuleEvaluator().evaluate(overflow_vector)

        self.assertEqual(bounded_vector, overflow_vector)
        self.assertEqual(bounded_rules, overflow_rules)

if __name__ == "__main__":
    unittest.main()
