"""Unit tests for corpus parsing (CSIC + ECML formats)."""

import unittest
from pathlib import Path

from waf_transformer.data.parsers import (
    detect_format,
    parse_corpus_file,
)

FIXTURES = Path(__file__).parent / "fixtures"
COOKIES = ("JSESSIONID", "PHPSESSID", "sid", "session", "connect.sid")


class TestParsers(unittest.TestCase):
    def test_detect_format(self):
        csic = (FIXTURES / "csic_block.txt").read_text()
        ecml = (FIXTURES / "ecml_block.txt").read_text()
        self.assertEqual(detect_format(csic), "annotated")
        self.assertEqual(detect_format(ecml), "annotated")
        self.assertEqual(detect_format("GET / HTTP/1.1\nHost: x\n"), "csic_original")

    def test_parse_csic_fixture(self):
        recs = list(parse_corpus_file(FIXTURES / "csic_block.txt", "csic_2010", COOKIES))
        self.assertEqual(len(recs), 3)
        attack = recs[0]
        self.assertEqual(attack.label.class_, "attack")
        self.assertEqual(attack.label.label_source, "dataset")
        self.assertEqual(attack.label.attack_category, "untyped")  # CSIC has no family labels
        self.assertTrue(attack.group_id.startswith("sess:JSESSIONID=372D"))
        self.assertIn("caracteristicas.jsp", attack.path)
        self.assertEqual(attack.query_string, "idA=2'+or+'1'%3D'1")

        benign = recs[1]
        self.assertEqual(benign.label.class_, "benign")
        self.assertEqual(benign.body, "")  # literal "null" body -> empty

        post = recs[2]
        self.assertEqual(post.method, "POST")
        self.assertIn("UNION", post.body)

    def test_parse_ecml_fixture(self):
        recs = list(parse_corpus_file(FIXTURES / "ecml_block.txt", "ecml_pkdd_2007", COOKIES))
        self.assertEqual(len(recs), 3)
        by_id = {r.id.split(":")[-1]: r for r in recs}
        self.assertEqual(by_id["48769"].label.attack_category, "xpath_injection")
        self.assertFalse(by_id["48769"].label.in_scope)  # out-of-scope family
        self.assertEqual(by_id["50001"].label.attack_category, "sql_injection")
        self.assertTrue(by_id["50001"].label.in_scope)
        self.assertEqual(by_id["50002"].label.attack_category, "xss")
        # no session cookie here -> Client-ip grouping
        self.assertEqual(by_id["50002"].group_id, "ip:232.245.220.246")

    def test_body_truncation_flag(self):
        recs = list(
            parse_corpus_file(FIXTURES / "csic_block.txt", "csic_2010", COOKIES, body_max_bytes=10)
        )
        self.assertTrue(recs[0].body_truncated or recs[2].body_truncated)

    def test_block_ids_unique_across_files(self):
        """CSIC's ModSecurity ids repeat between files — record ids must not."""
        import tempfile

        from waf_transformer.data.ingest import ingest_raw_dir

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "csic_2010"
            src.mkdir()
            (src / "a.txt").write_text((FIXTURES / "csic_block.txt").read_text())
            (src / "b.txt").write_text((FIXTURES / "csic_block.txt").read_text())
            recs = ingest_raw_dir(tmp, COOKIES, 8192, verbose=False)
            self.assertEqual(len(recs), 6)  # 3 blocks x 2 files, none dropped
            self.assertEqual(len({r.id for r in recs}), 6)


if __name__ == "__main__":
    unittest.main()
