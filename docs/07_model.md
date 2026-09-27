# Step 7 — Model Architecture

**Status: implemented** (`waf_transformer/modeling/model.py`,
`tests/test_model.py`). Config: `[model]` in `config/scope.toml`.

## Decision: small encoder-only transformer, trained from scratch

The plan: *"You don't need a massive model like GPT. A small encoder-only
transformer (similar to BERT but much smaller) is the right choice. Think
4–6 layers, 256–512 dimensions, 8 attention heads."* — implemented literally:

```
token emb (266 × 256) + learned positional emb (384 × 256)
  → 4 × TransformerEncoderLayer(d_model=256, nhead=8, FFN=1024, GELU, pre-LN)
  → LayerNorm → [CLS] pooling → MLP head (256→256→1) → logit
```

| Property | Value |
|---|---|
| Parameters | ~3.4 M |
| Layers / d_model / heads / FFN | 4 / 256 / 8 / 1024 |
| Output | single logit; `sigmoid` = p(malicious) |
| Max sequence | 384 tokens |
| Padding | `src_key_padding_mask`, `[PAD]` id 0 |

Unit-tested: parameter count stays in the 1–10 M "small encoder" band, output
shape is `[B]`, and **padding does not change the score** (eval mode).

## Why not fine-tune a pretrained BERT?

The plan's optional fast path. Rejected for v1:

1. **Domain mismatch** — code/text-pretrained embeddings do not know `S%45LECT`,
   `0x27274f52`, or anonymized ECML gibberish; the byte tokenizer wouldn't use
   their vocabularies anyway (a pretrained checkpoint would need its own
   tokenizer, losing the field-structure design).
2. **Serving constraints** — a BERT-base (110 M params) won't make the 10 ms
   p99 budget on CPU without heavy distillation; 3.4 M params quantizes to
   ~4 MB and runs in single-digit milliseconds.
3. Training from scratch on 155k labelled requests is cheap at this size.

Revisit if (a) data volume grows into the millions, or (b) multilingual
payloads demand richer subword features — then distill *into* this shape
rather than serving the big model.

## Model-selection story (ties to Step 8)

The head is binary because the enforcement question is binary. Attack
category/technique stays in the dataset as metadata for per-family analysis
(`evaluate.py` breaks recall down per category) and future multi-head variants.
