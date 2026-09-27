"""Unit tests for metrics (Step 8: precision/recall, not accuracy)."""

import unittest

from waf_transformer.modeling.metrics import (
    binary_confusion,
    percentile,
    precision_recall_f1,
    recall_by_group,
    threshold_for_min_recall,
)


class TestMetrics(unittest.TestCase):
    def test_perfect_separation(self):
        y = [0, 0, 1, 1]
        s = [0.1, 0.2, 0.8, 0.9]
        m = precision_recall_f1(y, s, 0.5)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1"], 1.0)

    def test_all_safe_is_useless(self):
        # the plan's example: on realistic (mostly-benign) traffic a model
        # labeling everything safe gets high accuracy but zero recall
        y = [0] * 9 + [1]
        s = [0.1] * 9 + [0.2]
        m = precision_recall_f1(y, s, 0.5)
        self.assertGreater(m["accuracy"], 0.8)
        self.assertEqual(m["recall"], 0.0)

    def test_confusion_counts(self):
        c = binary_confusion([1, 1, 0, 0], [0.9, 0.2, 0.8, 0.1], 0.5)
        self.assertEqual(c, {"tp": 1, "fp": 1, "tn": 1, "fn": 1})

    def test_threshold_for_min_recall(self):
        y = [0, 0, 0, 1, 1, 1]
        s = [0.1, 0.2, 0.55, 0.6, 0.8, 0.9]
        op = threshold_for_min_recall(y, s, min_recall=1.0)
        self.assertEqual(op["recall"], 1.0)
        # highest precision at full recall: threshold <= 0.6 catches all
        self.assertLessEqual(op["threshold"], 0.6)
        self.assertGreaterEqual(op["precision"], 2 / 3)

    def test_recall_by_group(self):
        y = [1, 1, 1, 0]
        s = [0.9, 0.1, 0.8, 0.9]
        g = ["xss", "xss", "sql_injection", "benign"]
        out = recall_by_group(y, s, g, 0.5)
        self.assertEqual(out["xss"]["recall"], 0.5)
        self.assertEqual(out["sql_injection"]["recall"], 1.0)
        self.assertNotIn("benign", out)  # no positives

    def test_percentile(self):
        vals = [1.0, 2.0, 3.0, 4.0, 100.0]
        self.assertEqual(percentile(vals, 50), 3.0)
        self.assertEqual(percentile(vals, 100), 100.0)
        self.assertEqual(percentile([], 50), 0.0)


if __name__ == "__main__":
    unittest.main()
