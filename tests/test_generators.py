"""Unit tests for the synthetic generators (Step 4 attack simulation)."""

import unittest

from waf_transformer.data.generate_attacks import make_attack_records
from waf_transformer.data.label import type_attack
from waf_transformer.data.synthesize_normal import make_normal_records


class TestAttackGenerator(unittest.TestCase):
    def test_deterministic_with_seed(self):
        a = make_attack_records(20, seed=42)
        b = make_attack_records(20, seed=42)
        self.assertEqual([r.to_json() for r in a], [r.to_json() for r in b])

    def test_labels_and_taxonomy(self):
        recs = make_attack_records(50, seed=1)
        for r in recs:
            self.assertEqual(r.label.class_, "attack")
            self.assertIn(r.label.attack_category, ("sql_injection", "xss"))
            self.assertTrue(r.label.in_scope)
            self.assertTrue(r.group_id.startswith("gen:"))

    def test_template_groups_hold_mutations_together(self):
        recs = make_attack_records(37, seed=5)
        groups = {}
        for r in recs:
            groups.setdefault(r.meta["base_template"], set()).add(r.group_id)
        for tmpl, gids in groups.items():
            self.assertEqual(len(gids), 1, f"template {tmpl} split across groups")

    def test_varied_placements(self):
        recs = make_attack_records(200, seed=9)
        placements = {r.meta["placement"] for r in recs}
        self.assertGreaterEqual(len(placements), 5)

    def test_varied_mutators(self):
        recs = make_attack_records(200, seed=9)
        mutators = {r.meta["mutator"] for r in recs}
        self.assertGreaterEqual(len(mutators), 6)

    def test_heuristics_recognize_generated_attacks(self):
        # The detector should see through our own obfuscation at least
        # partially — a floor of 70% typed coverage on 300 samples.
        recs = make_attack_records(300, seed=13)
        hits = sum(1 for r in recs if type_attack(r.blob())[0] is not None)
        self.assertGreaterEqual(hits / len(recs), 0.7)


class TestNormalGenerator(unittest.TestCase):
    def test_all_benign_and_grouped(self):
        recs = make_normal_records(100, seed=3)
        self.assertEqual(len(recs), 100)
        for r in recs:
            self.assertEqual(r.label.class_, "benign")
            self.assertTrue(r.group_id.startswith("sess:"))

    def test_sessions_group_multiple_requests(self):
        recs = make_normal_records(200, seed=4)
        from collections import Counter

        counts = Counter(r.group_id for r in recs)
        self.assertGreater(len(counts), 5)          # many sessions
        self.assertGreater(max(counts.values()), 2)  # multi-request sessions

    def test_deterministic_with_seed(self):
        a = make_normal_records(50, seed=8)
        b = make_normal_records(50, seed=8)
        self.assertEqual([r.to_json() for r in a], [r.to_json() for r in b])


if __name__ == "__main__":
    unittest.main()
