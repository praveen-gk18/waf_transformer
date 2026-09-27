"""Step 7 — small encoder-only transformer (BERT-shaped, WAF-sized).

~3.4M parameters: 4 layers, d_model 256, 8 heads, FFN 1024 — the plan's
"much smaller than GPT" encoder. Binary head: pooled [CLS] state -> logit;
sigmoid gives p(malicious) at inference.
"""

from __future__ import annotations

import torch
import torch.nn as nn

from ..config import ModelSpec


class WafEncoder(nn.Module):
    """Encoder-only transformer for binary request classification."""

    def __init__(self, vocab_size: int, spec: ModelSpec, max_len: int = 512):
        super().__init__()
        self.spec = spec
        self.max_len = max_len
        self.tok_embed = nn.Embedding(vocab_size, spec.d_model, padding_idx=0)
        self.pos_embed = nn.Embedding(max_len, spec.d_model)
        layer = nn.TransformerEncoderLayer(
            d_model=spec.d_model,
            nhead=spec.nhead,
            dim_feedforward=spec.dim_feedforward,
            dropout=spec.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(layer, spec.num_layers)
        self.norm = nn.LayerNorm(spec.d_model)
        self.head = nn.Sequential(
            nn.Linear(spec.d_model, spec.d_model),
            nn.GELU(),
            nn.LayerNorm(spec.d_model),
            nn.Linear(spec.d_model, 1),
        )

    def forward(self, ids: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        """ids/mask: [B, L] -> logits [B]."""
        B, L = ids.shape
        positions = torch.arange(L, device=ids.device).unsqueeze(0)
        x = self.tok_embed(ids) + self.pos_embed(positions)
        # key_padding_mask: True where PAD
        x = self.encoder(x, src_key_padding_mask=~mask.bool())
        x = self.norm(x)
        cls = x[:, 0]  # [CLS] pooling
        return self.head(cls).squeeze(-1)

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def build_model(vocab_size: int, spec: ModelSpec, max_len: int) -> WafEncoder:
    return WafEncoder(vocab_size, spec, max_len)
