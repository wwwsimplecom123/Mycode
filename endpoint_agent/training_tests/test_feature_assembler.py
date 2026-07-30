from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

import numpy as np


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "training"))

from _fixtures import make_feature_vector
from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION
from shielddome_training import ASSEMBLER_SCHEMA_VERSION, FeatureAssembler


class FeatureAssemblerTests(unittest.TestCase):
    def test_layout_is_stable_deterministic_and_uses_unknown_buckets(self):
        vector = make_feature_vector(
            categorical_features=(
                ("sender_domain_state", "future-state"),
                ("reply_to_domain_state", "present"),
                ("auth_spf_value", "pass"),
                ("auth_dkim_value", "future-auth"),
                ("auth_dmarc_value", "missing"),
                ("language", "future-language"),
            ),
            missing_value_mask=("reply_to", "future-mask"),
        )
        assembler = FeatureAssembler()

        first = assembler.transform(vector)
        second = assembler.transform(vector)
        batch = assembler.transform_many((vector, vector))

        self.assertEqual(ASSEMBLER_SCHEMA_VERSION, "1.0")
        self.assertEqual(assembler.output_dimension, 140)
        self.assertEqual(len(assembler.feature_names), 140)
        self.assertEqual(assembler.feature_names[0], "numeric:subject_present")
        self.assertEqual(assembler.feature_names[25], "numeric:intent_impersonation_count")
        self.assertEqual(assembler.feature_names[-1], "missing:unknown")
        self.assertEqual(
            hashlib.sha256(
                json.dumps(
                    assembler.feature_names,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "8363cefc61a1b1972c630e199280f6850b90d243fd7a1f849909175dbb77146f",
        )
        np.testing.assert_array_equal(first, second)
        np.testing.assert_array_equal(batch[0], first)
        np.testing.assert_array_equal(batch[1], first)
        self.assertEqual(first.dtype, np.float32)
        self.assertEqual(
            first[assembler.feature_names.index("categorical:sender_domain_state=unknown")],
            1.0,
        )
        self.assertEqual(
            first[assembler.feature_names.index("categorical:auth_dkim_value=unknown")],
            1.0,
        )
        self.assertEqual(
            first[assembler.feature_names.index("categorical:language=unknown")],
            1.0,
        )
        self.assertEqual(
            first[assembler.feature_names.index("missing:reply_to")],
            1.0,
        )
        self.assertEqual(
            first[assembler.feature_names.index("missing:unknown")],
            1.0,
        )

    def test_rejects_incompatible_feature_schema(self):
        vector = replace(make_feature_vector(), schema_version="future")

        with self.assertRaisesRegex(ValueError, "^feature_schema_mismatch$"):
            FeatureAssembler().transform(vector)

    def test_layout_does_not_expose_private_text_or_dynamic_vocabulary(self):
        private_values = (
            "password=fictional-secret",
            "token=fictional-token",
            "https://portal.example.test/login?token=fictional",
            "C:\\Users\\Fictional\\mail.eml",
        )
        assembler = FeatureAssembler()
        vector = make_feature_vector()
        serialized = repr((assembler.feature_names, assembler.transform(vector)))

        self.assertIsNone(vector.text_input)
        for private_value in private_values:
            self.assertNotIn(private_value, serialized)
        self.assertNotIn("token:", serialized.casefold())


if __name__ == "__main__":
    unittest.main()
