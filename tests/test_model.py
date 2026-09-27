"""Unit tests for the encoder model + losses (torch). Skips if torch missing."""

import unittest

try:
    import torch

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from waf_transformer.config import load_config

if HAS_TORCH:
    from waf_transformer.modeling.data import RequestDataset, collate
    from waf_transformer.modeling.losses import focal_bce, weighted_bce
    from waf_transformer.modeling.model import build_model
    from waf_transformer.modeling.tokenizer import VOCAB_SIZE, HttpByteTokenizer


@unittest.skipUnless(HAS_TORCH, "torch not installed")
class TestModel(unittest.TestCase):
    def setUp(self):
        cfg = load_config()
        self.cfg = cfg
        self.model = build_model(VOCAB_SIZE, cfg.model, cfg.tokenizer.max_len)

    def test_parameter_count_is_small(self):
        n = self.model.count_parameters()
        # the plan's "small encoder": well under GPT-scale, around ~3-4M
        self.assertGreater(n, 1_000_000)
        self.assertLess(n, 10_000_000)

    def test_forward_shape(self):
        ids = torch.randint(10, VOCAB_SIZE, (3, 40))
        mask = torch.ones(3, 40, dtype=torch.long)
        logits = self.model(ids, mask)
        self.assertEqual(tuple(logits.shape), (3,))

    def test_padding_does_not_change_score(self):
        self.model.eval()  # dropout off — padding must be score-invariant
        ids = torch.randint(10, VOCAB_SIZE, (1, 30))
        mask = torch.ones(1, 30, dtype=torch.long)
        padded = torch.cat([ids, torch.zeros(1, 10, dtype=torch.long)], dim=1)
        pmask = torch.cat([mask, torch.zeros(1, 10, dtype=torch.long)], dim=1)
        with torch.no_grad():
            a = self.model(ids, mask)
            b = self.model(padded, pmask)
        self.assertTrue(torch.allclose(a, b, atol=1e-4))

    def test_losses_decrease_for_correct_predictions(self):
        logits = torch.tensor([4.0, -4.0])
        targets = torch.tensor([1.0, 0.0])
        easy = weighted_bce(logits, targets, 1.0)
        hard = weighted_bce(-logits, targets, 1.0)
        self.assertLess(float(easy), float(hard))
        fl_easy = focal_bce(logits, targets)
        fl_hard = focal_bce(-logits, targets)
        self.assertLess(float(fl_easy), float(fl_hard))

    def test_dataset_and_collate(self):
        tok = HttpByteTokenizer(self.cfg.tokenizer)

        class R:
            method = "GET"
            path = "/x"
            query_string = "id=1"
            body = ""
            headers = [("Host", "x")]
            label = type("L", (), {"class_": "attack"})()

        ds = RequestDataset([R(), R()], tok)
        ids, mask, labels = collate([ds[0], ds[1]])
        self.assertEqual(ids.shape, mask.shape)
        self.assertEqual(float(labels.sum()), 2.0)


if __name__ == "__main__":
    unittest.main()
