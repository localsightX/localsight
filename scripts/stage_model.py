#!/usr/bin/env python3
"""Stage an operator-supplied model into the LocalSight registry.

Computes the SHA-256 of a local model artifact and registers it
(name, version, path, hash, source, license) in models/registry.json — the
same integrity contract the runtime enforces (`ModelRegistry.verify` refuses
a hash mismatch; nothing is ever fetched from a URL at runtime).

Examples:
    python scripts/stage_model.py --name plate_detector \
        --path models/staged/plate-det.onnx \
        --source "operator-trained YOLO plate detector" \
        --license "Apache-2.0"

    python scripts/stage_model.py --name attribute_prompts \
        --path models/staged/attribute_prompts.json \
        --source "CLIP ViT-B/32 prompt embeddings (operator-generated)" \
        --license "MIT (CLIP prompts/vectors)"

Stdlib-only by design (runs anywhere, including air-gapped hosts).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REGISTRY = Path("models/registry.json")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--name", required=True,
                    help="registry name (e.g. plate_detector, plate_ocr, "
                         "plate_charset, attribute_encoder, attribute_prompts)")
    ap.add_argument("--path", required=True, help="artifact path (relative to repo root)")
    ap.add_argument("--version", default="latest")
    ap.add_argument("--source", default="", help="provenance (where it came from)")
    ap.add_argument("--license", default="", help="artifact license (SPDX-ish)")
    ap.add_argument("--task", default="detect",
                    help="model task: detect | classify | embed | ocr | pose | prompts")
    ap.add_argument("--quantized", action="store_true",
                    help="artifact is INT8/FP16 post-training-quantized")
    args = ap.parse_args()

    path = Path(args.path)
    if not path.is_file():
        print(f"error: {path} does not exist — stage the artifact first", file=sys.stderr)
        return 1

    digest = sha256_of(path)
    rec = {
        "name": args.name,
        "version": args.version,
        "path": str(path),
        "hash_sha256": digest,
        "source": args.source,
        "license": args.license,
        "task": args.task,
        "quantized": bool(args.quantized),
    }

    data = {"models": []}
    if REGISTRY.exists():
        data = json.loads(REGISTRY.read_text())
    models = [m for m in data.get("models", [])
              if not (m["name"] == args.name and m["version"] == args.version)]
    models.append(rec)
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY.write_text(json.dumps({"models": models}, indent=2) + "\n")

    print(f"registered {args.name}@{args.version}")
    print(f"  path: {path}")
    print(f"  sha256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
