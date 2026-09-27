"""Unit tests for the byte-level HTTP tokenizer (Step 6)."""

import unittest

from waf_transformer.config import load_config
from waf_transformer.modeling.tokenizer import (
    BODY,
    CLS,
    METH,
    PAD,
    PATH,
    QUERY,
    SEP,
    TRUNC,
    VOCAB_SIZE,
    HttpByteTokenizer,
    batch_encode,
)


class TestTokenizer(unittest.TestCase):
    def setUp(self):
        self.tok = HttpByteTokenizer(load_config().tokenizer)

    def test_field_structure(self):
        enc = self.tok.encode("GET", "/item", "id=1", [("Host", "x")], "body")
        self.assertEqual(enc.ids[0], CLS)
        self.assertIn(METH, enc.ids)
        self.assertIn(PATH, enc.ids)
        self.assertIn(QUERY, enc.ids)
        self.assertIn(BODY, enc.ids)
        self.assertEqual(enc.ids[-1], SEP)
        self.assertFalse(enc.truncated_fields)

    def test_where_not_just_what(self):
        """Same bytes in query vs body produce different id sequences."""
        a = self.tok.encode("GET", "/x", "q=abc", [], "")
        b = self.tok.encode("GET", "/x", "", [], "q=abc")
        self.assertNotEqual(a.ids, b.ids)

    def test_byte_fidelity_no_oov(self):
        enc = self.tok.encode("GET", "/日本語", "q=%u0027", [], "\x00\x01 weird")
        for tid in enc.ids:
            self.assertTrue(0 <= tid < VOCAB_SIZE)
        # roundtrip of a pure-ASCII request
        enc2 = self.tok.encode("GET", "/abc", "", [], "")
        text = self.tok.decode(enc2.ids)
        self.assertIn("/abc", text)

    def test_truncation_flag(self):
        enc = self.tok.encode("GET", "/x", "q=" + "a" * 500, [], "b" * 500)
        self.assertIn("query", enc.truncated_fields)
        self.assertIn("body", enc.truncated_fields)
        self.assertIn(TRUNC, enc.ids)

    def test_hard_cap(self):
        enc = self.tok.encode("GET", "/" + "p" * 400, "q=" + "a" * 400, [("H", "v" * 400)], "b" * 400)
        self.assertLessEqual(len(enc.ids), self.tok.max_len)

    def test_batch_encode_padding(self):
        recs = [
            _rec("GET", "/a", "", "", ""),
            _rec("POST", "/bbbbbb", "q=1", "bodydata", "x"),
        ]
        ids, mask = batch_encode(self.tok, recs)
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(ids[0]), len(ids[1]))
        self.assertEqual(len(ids[0]), len(mask[0]))
        self.assertTrue(all(v == PAD or m == 1 for v, m in zip(ids[0], mask[0])))


def _rec(method, path, query, body, extra):
    class R:
        pass

    r = R()
    r.method, r.path, r.query_string, r.body = method, path, query, body
    r.headers = [("Host", "x")] if extra else []
    return r


if __name__ == "__main__":
    unittest.main()
