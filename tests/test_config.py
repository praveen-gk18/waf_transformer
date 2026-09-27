"""Unit tests for the scope contract loader (Phase 1 decisions stay valid)."""

import unittest

from waf_transformer.config import ConfigError, load_config
from waf_transformer.data.schema import IN_SCOPE_CATEGORIES


class TestConfig(unittest.TestCase):
    def test_loads_and_validates(self):
        cfg = load_config()
        self.assertEqual(cfg.objective, "binary")
        self.assertEqual(cfg.in_scope_categories, ("sql_injection", "xss"))
        self.assertLessEqual(cfg.latency.p99, cfg.latency.hard_cap)
        self.assertAlmostEqual(
            cfg.dataset.train_fraction + cfg.dataset.val_fraction + cfg.dataset.test_fraction, 1.0
        )

    def test_taxonomy_matches_code_constants(self):
        cfg = load_config()
        self.assertEqual(cfg.in_scope_categories, IN_SCOPE_CATEGORIES)

    def test_bad_fractions_rejected(self):
        from waf_transformer.config import DatasetRules

        rules = DatasetRules(
            train_fraction=0.5, val_fraction=0.15, test_fraction=0.15, seed=1,
            min_attack_ratio=0.05, target_attack_ratio=0.08, max_attack_ratio=0.9,
            oversample="attacks_if_scarce", val_test_ratio="natural",
            holdout_techniques=(), group_key_priority=("record_id",),
            session_cookie_names=("JSESSIONID",), body_max_bytes=100,
            body_overflow="truncate", header_max_count=10, header_value_max_bytes=100,
        )
        with self.assertRaises(ConfigError):
            rules.validate()  # fractions sum to 0.8


if __name__ == "__main__":
    unittest.main()
