"""Unit tests for labeling: heuristics, adjudication, corrections (Step 5)."""

import unittest

from waf_transformer.data.label import (
    adjudicate,
    enrich,
    label_records,
    type_attack,
)
from waf_transformer.data.schema import Label, RequestRecord


def rec(body: str = "", query: str = "", label: Label | None = None, rid: str = "r1") -> RequestRecord:
    return RequestRecord(
        id=rid,
        source="test",
        method="GET",
        path="/item",
        query_string=query,
        http_version="HTTP/1.1",
        headers=[("Host", "x")],
        body=body,
        label=label or Label(class_="unknown", label_source="unknown"),
    )


class TestHeuristics(unittest.TestCase):
    def test_union_sql_detected(self):
        cat, tech, conf = type_attack("GET /item?id=1 UNION SELECT password FROM users--")
        self.assertEqual(cat, "sql_injection")
        self.assertEqual(tech, "union_sql")
        self.assertEqual(conf, 0.9)

    def test_time_based_sql_detected(self):
        cat, tech, _ = type_attack("id=1'; WAITFOR DELAY '0:0:5'--")
        self.assertEqual((cat, tech), ("sql_injection", "time_based_sql"))

    def test_reflected_xss_detected(self):
        cat, tech, conf = type_attack("q=<script>alert(1)</script>")
        self.assertEqual(cat, "xss")
        self.assertEqual(conf, 0.9)

    def test_event_handler_xss_detected(self):
        cat, _, _ = type_attack("q=<img src=x onerror=alert(1)>")
        self.assertEqual(cat, "xss")

    def test_encoded_payload_detected_after_decode(self):
        cat, _, _ = type_attack("q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(cat, "xss")

    def test_double_encoded_detected(self):
        cat, _, _ = type_attack("q=%253Cscript%253Ealert(1)%253C%252Fscript%253E")
        self.assertEqual(cat, "xss")

    def test_benign_text_not_flagged(self):
        cat, _, _ = type_attack("GET /product/104?q=100%25 cotton socks")
        self.assertIsNone(cat)

    def test_out_of_scope_family_typed(self):
        cat, _, _ = type_attack("file=../../../../etc/passwd")
        self.assertEqual(cat, "path_traversal")


class TestAdjudication(unittest.TestCase):
    def test_priority_order(self):
        ds = Label(class_="benign", label_source="dataset")
        manual = Label(class_="attack", attack_category="xss", label_source="manual")
        self.assertEqual(adjudicate(ds, manual), manual)

    def test_unknown_loses_to_everything(self):
        unk = Label(class_="unknown", label_source="unknown")
        heur = Label(class_="attack", attack_category="sql_injection", label_source="heuristic")
        self.assertEqual(adjudicate(unk, heur), heur)


class TestEnrichment(unittest.TestCase):
    def test_untyped_attack_gets_category(self):
        r = rec(query="id=1 UNION SELECT 1,2 FROM users--", label=Label(class_="attack", attack_category="untyped", label_source="dataset"))
        r = enrich(r)
        self.assertEqual(r.label.attack_category, "sql_injection")
        self.assertEqual(r.label.label_source, "dataset")  # class source unchanged

    def test_unknown_with_signal_becomes_attack(self):
        r = rec(query="q=<svg/onload=alert(1)>")
        r = enrich(r)
        self.assertEqual(r.label.class_, "attack")
        self.assertEqual(r.label.label_source, "heuristic")

    def test_unknown_without_signal_stays_unknown(self):
        r = rec(query="q=shoes")
        r = enrich(r)
        self.assertEqual(r.label.class_, "unknown")  # never silently benign

    def test_weird_but_benign_stays_benign(self):
        r = rec(query="q=select+*+from+catalog+gifts", label=Label(class_="benign", label_source="synthetic"))
        r = enrich(r)
        self.assertEqual(r.label.class_, "benign")  # enrichment never downgrades


class TestLabelRecords(unittest.TestCase):
    def test_corrections_are_manual_and_win(self):
        r1 = rec(query="id=1 UNION SELECT 1 FROM x--", rid="a")
        r2 = rec(query="q=shoes", label=Label(class_="benign", label_source="dataset"), rid="b")
        corrections = {
            "a": {"class": "benign", "attack_category": None},
            "b": {"class": "attack", "attack_category": "xss"},
        }
        labeled, stats = label_records([r1, r2], corrections=corrections)
        self.assertEqual(labeled[0].label.class_, "benign")
        self.assertEqual(labeled[0].label.label_source, "manual")
        self.assertEqual(labeled[1].label.class_, "attack")
        self.assertEqual(stats["total"], 2)

    def test_waf_export_labels_attack(self):
        from waf_transformer.data.label import label_from_waf_export

        r = rec(query="q=anything", rid="w1", label=Label(class_="unknown", label_source="unknown"))
        waf = label_from_waf_export({"w1": "sql_injection"})
        labeled, _ = label_records([r], waf_labels=waf)
        self.assertEqual(labeled[0].label.class_, "attack")
        self.assertEqual(labeled[0].label.label_source, "waf_export")
        self.assertEqual(labeled[0].label.attack_category, "sql_injection")


if __name__ == "__main__":
    unittest.main()
