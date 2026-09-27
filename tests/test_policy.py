"""Unit tests for the enforcement policy (Step 12): thresholds + hot-reload + shadow."""

import os
import tempfile
import time
import unittest
from pathlib import Path

from waf_transformer.engine.policy import EnforcementPolicy

BASE = """\
[enforcement]
block_above = {block}
challenge_above = {challenge}
mode = "{mode}"
"""


def write_config(tmp: Path, block: float = 0.9, challenge: float = 0.6, mode: str = "shadow") -> Path:
    p = tmp / "scope.toml"
    p.write_text(BASE.format(block=block, challenge=challenge, mode=mode))
    return p


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_thresholds_map_to_actions(self):
        pol = EnforcementPolicy(write_config(self.dir, 0.9, 0.6, mode="block"))
        self.assertEqual(pol.decide(0.95), ("block", None))
        self.assertEqual(pol.decide(0.90), ("block", None))  # boundary inclusive
        self.assertEqual(pol.decide(0.7), ("challenge", None))
        self.assertEqual(pol.decide(0.59), ("allow", None))

    def test_shadow_mode_never_blocks(self):
        pol = EnforcementPolicy(write_config(self.dir, 0.9, 0.6, mode="shadow"))
        self.assertEqual(pol.decide(0.99), ("allow", "block"))
        self.assertEqual(pol.decide(0.7), ("allow", "challenge"))
        action, shadow = pol.decide(0.1)
        self.assertEqual((action, shadow), ("allow", None))

    def test_challenge_mode_upgrades_blocks_to_challenge(self):
        pol = EnforcementPolicy(write_config(self.dir, 0.9, 0.6, mode="challenge"))
        self.assertEqual(pol.decide(0.99), ("challenge", None))
        self.assertEqual(pol.decide(0.7), ("challenge", None))
        self.assertEqual(pol.decide(0.1), ("allow", None))

    def test_hot_reload_on_config_change(self):
        cfg = write_config(self.dir, 0.9, 0.6, mode="shadow")
        pol = EnforcementPolicy(cfg)
        self.assertEqual(pol.decide(0.8), ("allow", "challenge"))
        time.sleep(0.01)
        # rewrite with new thresholds + mode; bump mtime explicitly (fs granularity)
        write_config(self.dir, 0.95, 0.5, mode="block")
        os.utime(cfg, (time.time() + 2, time.time() + 2))
        self.assertTrue(pol.reload_if_changed())
        self.assertEqual(pol.state.mode, "block")
        self.assertEqual(pol.decide(0.8), ("challenge", None))  # now blocks? no: 0.8 < 0.95 -> challenge
        self.assertEqual(pol.decide(0.97), ("block", None))

    def test_invalid_thresholds_rejected(self):
        cfg = write_config(self.dir, 0.5, 0.9, mode="block")  # challenge > block
        with self.assertRaises(ValueError):
            EnforcementPolicy(cfg)


class FakePolicy:
    """Duck-typed policy for downstream tests."""

    class _S:
        mode = "shadow"
        block_above = 0.9
        challenge_above = 0.6
        version = "fake"

    state = _S()

    def reload_if_changed(self):
        return False

    def decide(self, score):
        if score >= 0.9:
            return "allow", "block"
        if score >= 0.6:
            return "allow", "challenge"
        return "allow", None


if __name__ == "__main__":
    unittest.main()
