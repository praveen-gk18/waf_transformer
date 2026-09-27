"""Export the trained encoder to ONNX + dynamic int8 (Step 9 optimization).

Produces ``artifacts/model.onnx`` and ``artifacts/model_int8.onnx`` for
ONNX Runtime serving (the Phase-4 latency path in docs/02_tech_stack.md).

Usage::

    python3 -m waf_transformer.modeling.export_onnx --checkpoint artifacts/run1/best.pt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import torch

from .evaluate import load_checkpoint
from .model import build_model  # noqa: F401  (re-export convenience)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export checkpoint to ONNX (+int8)")
    ap.add_argument("--checkpoint", type=Path, default=Path("artifacts/run1/best.pt"))
    ap.add_argument("--out", type=Path, default=Path("artifacts"))
    ap.add_argument("--max-len", type=int, default=512)
    args = ap.parse_args(argv)

    model, _ = load_checkpoint(args.checkpoint, torch.device("cpu"))
    model.eval()
    args.out.mkdir(parents=True, exist_ok=True)
    onnx_path = args.out / "model.onnx"

    dummy_ids = torch.ones(1, 16, dtype=torch.long)
    dummy_mask = torch.ones(1, 16, dtype=torch.long)
    torch.onnx.export(
        model,
        (dummy_ids, dummy_mask),
        str(onnx_path),
        input_names=["ids", "mask"],
        output_names=["logit"],
        dynamic_axes={"ids": {0: "batch", 1: "seq"}, "mask": {0: "batch", 1: "seq"}, "logit": {0: "batch"}},
        opset_version=17,
    )
    # torch>=2.6 writes external weights (model.onnx.data) by default; fold
    # them back in so the deployable artifact is one self-contained file.
    try:
        import onnx

        m = onnx.load(str(onnx_path))
        onnx.save(m, str(onnx_path), save_as_external_data=False)
        data_sidecar = onnx_path.with_suffix(".onnx.data")
        if data_sidecar.exists():
            data_sidecar.unlink()
    except Exception as exc:  # noqa: BLE001
        print(f"external-data fold-in skipped: {exc}")
    print(f"exported {onnx_path}")

    try:
        from onnxruntime.quantization import QuantType, quantize_dynamic

        int8_path = args.out / "model_int8.onnx"
        quantize_dynamic(
            str(onnx_path),
            str(int8_path),
            weight_type=QuantType.QInt8,
            extra_options={"MatMulConstBOnly": True},
        )
        print(f"exported {int8_path}")
    except Exception as exc:  # noqa: BLE001
        print(f"int8 quantization skipped: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
