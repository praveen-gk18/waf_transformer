"""Dataset + batching for training/eval (torch)."""

from __future__ import annotations

import random
from pathlib import Path

import torch
from torch.utils.data import DataLoader, Dataset

from ..data.schema import read_jsonl
from .tokenizer import HttpByteTokenizer


def load_records(path: Path, max_records: int = 0, seed: int = 0) -> list:
    """Load RequestRecords; optional stratified (by class) subsample.

    ``max_records`` > 0 samples at MOST that many while keeping the class mix;
    0 means everything. Used to keep CPU-sandbox training runs tractable —
    production trains on the full split.
    """
    recs = [r for r in read_jsonl(path) if r.label.class_ in ("benign", "attack")]
    if max_records and len(recs) > max_records:
        rng = random.Random(seed)
        benign = [r for r in recs if r.label.class_ == "benign"]
        attack = [r for r in recs if r.label.class_ == "attack"]
        frac = max_records / len(recs)
        keep = (
            rng.sample(benign, max(1, int(len(benign) * frac)))
            + rng.sample(attack, max(1, int(len(attack) * frac)))
        )
        rng.shuffle(keep)
        recs = keep
    return recs


class RequestDataset(Dataset):
    """Pre-encoded token id tensors + labels."""

    def __init__(self, records: list, tokenizer: HttpByteTokenizer):
        self.items = []
        for r in records:
            enc = tokenizer.encode_record(r)
            self.items.append(
                (
                    torch.tensor(enc.ids, dtype=torch.long),
                    1.0 if r.label.class_ == "attack" else 0.0,
                )
            )

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, idx: int):
        return self.items[idx]


def collate(batch):
    """Pad to the longest sequence in the batch -> (ids, mask, labels)."""
    seqs, labels = zip(*batch)
    width = max(len(s) for s in seqs)
    ids = torch.zeros(len(seqs), width, dtype=torch.long)
    mask = torch.zeros(len(seqs), width, dtype=torch.long)
    for i, s in enumerate(seqs):
        ids[i, : len(s)] = s
        mask[i, : len(s)] = 1
    return ids, mask, torch.tensor(labels, dtype=torch.float)


def make_loader(
    dataset: Dataset, batch_size: int, shuffle: bool, seed: int = 0, bucket: bool = False
) -> DataLoader:
    """Batch loader. ``bucket=True`` groups same-length sequences into batches
    (removes padding waste) and sizes each batch to a memory budget so long
    batches shrink (attention is O(L^2) — 24 x 384 tokens overruns 3 GB RAM).
    """
    if bucket:
        import random as _random

        order = sorted(range(len(dataset)), key=lambda i: len(dataset[i][0]))
        batches: list[list[int]] = []
        cur: list[int] = []
        for i in order:
            length = max(len(dataset[i][0]), 1)
            # Memory budget: attention activations scale ~batch * L^2. Kept
            # tight so a full-length batch stays well under 2 GB (3 GB box).
            size_cap = max(2, min(batch_size, int(300_000 / (length * length))))
            if cur and len(cur) >= size_cap:
                batches.append(cur)
                cur = []
            cur.append(i)
        if cur:
            batches.append(cur)
        _random.Random(seed).shuffle(batches)
        return DataLoader(
            dataset, batch_sampler=batches, collate_fn=collate, num_workers=0
        )
    gen = torch.Generator()
    gen.manual_seed(seed)
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        generator=gen if shuffle else None,
        collate_fn=collate,
        num_workers=0,
    )
