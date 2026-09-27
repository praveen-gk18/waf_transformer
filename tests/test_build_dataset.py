"""Unit tests for dataset building: leakage, ratios, holdout (Steps 5 & 8)."""

import json
import random
import unittest

from waf_transformer.config import load_config
from waf_transformer.data.build_dataset import (
    LeakageError,
    audit_split_leakage,
    balance_train,
    build,
    group_aware_split,
)
from waf_transformer.data.schema import Label, RequestRecord, read_jsonl, write_jsonl


def make_rec(i: int, cls: str, group: str, technique: str | None = None, source: str = "test") -> RequestRecord:
    return RequestRecord(
        id=f"{source}:{i}",
        source=source,
        method="GET",
        path=f"/item/{i}",
        query_string="q=1",
        http_version="HTTP/1.1",
        headers=[("Host", "x")],
        body="",
        label=Label(
            class_=cls,
            attack_category="sql_injection" if cls == "attack" else None,
            attack_technique=technique,
            in_scope=True,
            label_source="dataset",
        ),
        group_id=group,
    )


def synth_pool(rng: random.Random, n_groups: int = 60, per_group: int = 4) -> list[RequestRecord]:
    recs = []
    i = 0
    for g in range(n_groups):
        # each group is mostly one class (a session or a campaign)
        cls = "attack" if g % 3 == 0 else "benign"
        for _ in range(per_group):
            recs.append(make_rec(i, cls, group=f"g{g}", technique=None))
            i += 1
    rng.shuffle(recs)
    return recs


class TestGroupSplit(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config()
        self.rng = random.Random(7)

    def test_no_group_leakage(self):
        recs = synth_pool(self.rng)
        splits = group_aware_split(recs, self.cfg)
        audit_split_leakage(splits)
        groups = [set(r.group_id for r in recs) for recs in splits.values()]
        self.assertTrue(groups[0].isdisjoint(groups[1]))
        self.assertTrue(groups[0].isdisjoint(groups[2]))
        self.assertTrue(groups[1].isdisjoint(groups[2]))

    def test_split_sizes_roughly_match_fractions(self):
        recs = synth_pool(self.rng)
        splits = group_aware_split(recs, self.cfg)
        n = len(recs)
        self.assertAlmostEqual(len(splits["train"]) / n, 0.70, delta=0.08)
        self.assertAlmostEqual(len(splits["val"]) / n, 0.15, delta=0.08)
        self.assertAlmostEqual(len(splits["test"]) / n, 0.15, delta=0.08)

    def test_leakage_detected(self):
        bad = {
            "train": [make_rec(0, "benign", "gX")],
            "val": [make_rec(1, "benign", "gX")],
            "test": [],
        }
        with self.assertRaises(LeakageError):
            audit_split_leakage(bad)

    def test_deterministic_with_seed(self):
        recs = synth_pool(self.rng)
        a = group_aware_split(recs, self.cfg)
        b = group_aware_split(recs, self.cfg)
        self.assertEqual([r.id for r in a["train"]], [r.id for r in b["train"]])


class TestBalance(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config()

    def test_oversamples_when_attacks_scarce(self):
        recs = [make_rec(i, "attack", f"ga{i}") for i in range(5)]
        recs += [make_rec(100 + i, "benign", f"gb{i}") for i in range(95)]
        out = balance_train(recs, self.cfg)
        n_attack = sum(1 for r in out if r.label.class_ == "attack")
        ratio = n_attack / len(out)
        self.assertGreaterEqual(ratio, self.cfg.dataset.min_attack_ratio)
        self.assertLessEqual(ratio, 0.12)  # ~target 8%, integer rounding slack
        self.assertTrue(any(r.meta.get("oversampled") for r in out))

    def test_no_resampling_when_floor_satisfied(self):
        recs = [make_rec(i, "attack", f"ga{i}") for i in range(30)]
        recs += [make_rec(100 + i, "benign", f"gb{i}") for i in range(70)]
        out = balance_train(recs, self.cfg)
        self.assertEqual(len(out), len(recs))  # public-corpus case: keep everything
        self.assertFalse(any(r.meta.get("oversampled") for r in out))


class TestBuild(unittest.TestCase):
    def test_end_to_end_build(self):
        import tempfile
        from pathlib import Path

        cfg = load_config()
        rng = random.Random(11)
        recs = synth_pool(rng, n_groups=90, per_group=3)
        # add some holdout-technique attacks (time_based_sql) -> test_unseen only
        for i in range(12):
            recs.append(make_rec(900 + i, "attack", group=f"hold{i}", technique="time_based_sql"))

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            inp = tmp / "labeled.jsonl"
            out_dir = tmp / "processed"
            write_jsonl(inp, recs)
            stats = build(inp, out_dir, cfg)

            self.assertEqual(stats["leakage_audit"], "passed")
            self.assertEqual(stats["test_unseen"]["records"], 12)
            self.assertGreaterEqual(stats["train_attack_ratio"], cfg.dataset.min_attack_ratio)

            # files exist and are loadable
            train = list(read_jsonl(out_dir / "train.jsonl.gz"))
            unseen = list(read_jsonl(out_dir / "test_unseen.jsonl.gz"))
            self.assertEqual(len(unseen), 12)
            self.assertTrue(all(r.label.attack_technique == "time_based_sql" for r in unseen))

            # holdout groups never appear in main splits
            main_groups = {r.group_id for r in train}
            self.assertTrue(all(r.group_id not in main_groups for r in unseen))

            # splits index matches actual data
            index = json.loads((out_dir / "splits_index.json").read_text())
            self.assertEqual(set(index["test_unseen"]), {r.group_id for r in unseen})

    def test_unknown_records_dropped(self):
        import tempfile
        from pathlib import Path

        cfg = load_config()
        recs = synth_pool(random.Random(3), n_groups=30, per_group=2)
        recs.append(make_rec(9999, "attack", "gx"))
        recs[-1].label = Label(class_="unknown", label_source="unknown")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            inp = tmp / "labeled.jsonl"
            write_jsonl(inp, recs)
            stats = build(inp, tmp / "processed", cfg)
            self.assertEqual(stats["overall"]["records"], len(recs) - 1)


if __name__ == "__main__":
    unittest.main()
