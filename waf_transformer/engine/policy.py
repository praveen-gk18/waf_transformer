"""Step 12 — enforcement policy: score -> allow / challenge / block.

The plan: *"These thresholds should be configurable without redeploying the
model. Store them in a config file or a feature flag system."*

This reads ``[enforcement]`` from config/scope.toml and **hot-reloads when the
file changes** (checked per decision via mtime — a ~2 µs stat). Editing the
config file is enough; no restart, no model redeploy.

**Shadow mode** (Phase 5's Step 13 requirement, honored from day one): with
``mode = "shadow"`` nothing is ever blocked — the policy reports ``allow``
while recording the ``shadow_action`` the model *would* have taken. Flip
``mode`` to ``challenge``/``block`` in the config file when ready to enforce.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass

from ..config import DEFAULT_CONFIG_PATH

VALID_MODES = ("shadow", "challenge", "block")


@dataclass
class PolicyState:
    mode: str
    block_above: float
    challenge_above: float
    version: str  # short hash of the enforcement config content
    enforce_percent: float = 100.0  # Step 14: % of traffic actually enforced


class EnforcementPolicy:
    """Threshold policy with hot-reload. Thread-safe for read-mostly use."""

    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self._path = str(config_path)
        self._mtime: float = -1.0
        self._state = self._load()

    # -- loading / hot-reload -------------------------------------------
    def _load(self) -> PolicyState:
        # Parse only [enforcement] — the policy file contract is standalone
        # (editing thresholds must not require the rest of the AppCfg schema).
        import tomllib

        with open(self._path, "rb") as fh:
            enf = tomllib.load(fh).get("enforcement", {})
        mode = str(enf.get("mode", "shadow"))
        if mode not in VALID_MODES:
            raise ValueError(f"enforcement.mode must be one of {VALID_MODES}, got {mode!r}")
        block_above = float(enf.get("block_above", 0.9))
        challenge_above = float(enf.get("challenge_above", 0.6))
        if not 0.0 <= challenge_above <= block_above <= 1.0:
            raise ValueError("require 0 <= challenge_above <= block_above <= 1")
        enforce_percent = float(enf.get("enforce_percent", 100.0))
        if not 0.0 <= enforce_percent <= 100.0:
            raise ValueError("require 0 <= enforce_percent <= 100")
        raw = f"{mode}:{block_above}:{challenge_above}:{enforce_percent}:{self._path}".encode()
        version = hashlib.sha256(raw).hexdigest()[:12]
        self._mtime = os.stat(self._path).st_mtime
        return PolicyState(mode, block_above, challenge_above, version, enforce_percent)

    def reload_if_changed(self) -> bool:
        """Cheap per-request check; reloads [enforcement] when the file changes."""
        try:
            mtime = os.stat(self._path).st_mtime
        except OSError:
            return False
        if mtime != self._mtime:
            self._state = self._load()
            return True
        return False

    def force_reload(self) -> None:
        self._state = self._load()

    # -- decisions -------------------------------------------------------
    @property
    def state(self) -> PolicyState:
        return self._state

    @staticmethod
    def _sampled_in(key: str | None, enforce_percent: float) -> bool:
        """Deterministic traffic sampling for staged rollouts (Step 14).

        The same key always lands on the same side of the cut, so a given
        client's experience is consistent while `enforce_percent` is stable.
        """
        if enforce_percent >= 100.0:
            return True
        if enforce_percent <= 0.0:
            return False
        if key is None:
            key = "all"  # no key -> treat everything uniformly
        h = int.from_bytes(hashlib.sha256(key.encode()).digest()[:4], "big") % 100
        return h < enforce_percent

    def decide(self, score: float, key: str | None = None) -> tuple[str, str | None]:
        """Return (action, shadow_action).

        action is what to DO now (in shadow mode, or outside the enforced
        traffic sample, always 'allow'); shadow_action is what the thresholds
        imply in those cases (None when nothing would have happened).
        """
        st = self._state
        if score >= st.block_above:
            would = "block"
        elif score >= st.challenge_above:
            would = "challenge"
        else:
            would = "allow"
        enforcing = (
            st.mode != "shadow"
            and self._sampled_in(key, st.enforce_percent)
        )
        if not enforcing:
            return "allow", (would if would != "allow" else None)
        if st.mode == "challenge":
            # challenge mode: no hard blocks yet — challenge the would-blocks too
            return (would if would != "block" else "challenge"), None
        return would, None
