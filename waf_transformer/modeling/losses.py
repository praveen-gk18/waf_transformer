"""Step 8 losses — class-weighted BCE (default) and focal loss.

The plan: binary cross-entropy, plus class weighting or focal loss for the
benign/attack imbalance. Both are provided; scope.toml [training].loss picks.
"""

from __future__ import annotations

import torch
import torch.nn.functional as F


def weighted_bce(logits: torch.Tensor, targets: torch.Tensor, pos_weight: float) -> torch.Tensor:
    """BCE with logits, attacks weighted up (pos_weight = n_benign / n_attack)."""
    pw = torch.tensor([pos_weight], device=logits.device, dtype=logits.dtype)
    return F.binary_cross_entropy_with_logits(logits, targets, pos_weight=pw)


def focal_bce(
    logits: torch.Tensor, targets: torch.Tensor, gamma: float = 2.0, alpha: float = 0.25
) -> torch.Tensor:
    """Sigmoid focal loss (Lin et al.) — down-weights easy examples."""
    probs = torch.sigmoid(logits)
    targets = targets.float()
    bce = F.binary_cross_entropy_with_logits(logits, targets, reduction="none")
    p_t = probs * targets + (1 - probs) * (1 - targets)
    alpha_t = alpha * targets + (1 - alpha) * (1 - targets)
    loss = alpha_t * (1 - p_t) ** gamma * bce
    return loss.mean()
