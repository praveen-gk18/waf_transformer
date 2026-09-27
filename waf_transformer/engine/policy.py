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
        raw = f"{mode}:{block_above}:{challenge_above}:{self._path}".encode()
        version = hashlib.sha256(raw).hexdigest()[:12]
        self._mtime = os.stat(self._path).st_mtime
        return PolicyState(mode, block_above, challenge_above, version)

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

    def decide(self, score: float) -> tuple[str, str | None]:
        """Return (action, shadow_action).

        action is what to DO now (in shadow mode always 'allow');
        shadow_action is what the thresholds imply (None outside shadow mode).
        """
        st = self._state
        if score >= st.block_above:
            would = "block"
        elif score >= st.challenge_above:
            would = "challenge"
        else:
            would = "allow"
        if st.mode == "shadow":
            return "allow", (would if would != "allow" else None)
        if st.mode == "challenge":
            # challenge mode: no hard blocks yet — challenge the would-blocks too
            return (would if would != "block" else "challenge"), None
        return would, None
