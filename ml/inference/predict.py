#!/usr/bin/env python3
"""
MORPHEX Contextual Secret Classifier — ONNX Inference

Lightweight inference module that loads the exported ONNX model and
classifies code-context windows as SECRET (1) or NOT_SECRET (0).

Can be used standalone for testing or imported as a library.

Usage:
    python predict.py --model ../models/distilbert-secret-classifier \
                      --text "aws_secret_key = 'AKIA...'"

    python predict.py --model ../models/distilbert-secret-classifier \
                      --file suspicious_code.py --line 42
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np


class SecretClassifier:
    """ONNX-based contextual secret classifier."""

    def __init__(self, model_dir: str):
        import onnxruntime as ort
        from transformers import DistilBertTokenizerFast

        self.model_dir = model_dir

        meta_path = os.path.join(model_dir, "training_metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path) as fh:
                self.metadata = json.load(fh)
        else:
            self.metadata = {"max_length": 512}

        self.max_length = self.metadata.get("max_length", 512)
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)

        onnx_path = os.path.join(model_dir, "model.onnx")
        if not os.path.exists(onnx_path):
            raise FileNotFoundError(f"ONNX model not found at {onnx_path}")

        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = (
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        )
        sess_opts.intra_op_num_threads = 1
        sess_opts.inter_op_num_threads = 1
        self.session = ort.InferenceSession(onnx_path, sess_opts)

    def predict(self, text: str) -> dict:
        """Classify a single context window.

        Returns:
            {"label": 0|1, "label_name": str,
             "confidence": float, "latency_ms": float}
        """
        start = time.perf_counter()

        enc = self.tokenizer(
            text,
            return_tensors="np",
            padding="max_length",
            max_length=self.max_length,
            truncation=True,
        )

        outputs = self.session.run(
            None,
            {
                "input_ids": enc["input_ids"].astype(np.int64),
                "attention_mask": enc["attention_mask"].astype(np.int64),
            },
        )
        logits = outputs[0][0]

        probs = _softmax(logits)
        pred = int(np.argmax(probs))
        confidence = float(probs[pred])
        elapsed_ms = (time.perf_counter() - start) * 1000

        labels_map = self.metadata.get("labels", {0: "NOT_SECRET", 1: "SECRET"})
        label_name = labels_map.get(str(pred), labels_map.get(pred, "UNKNOWN"))

        return {
            "label": pred,
            "label_name": label_name,
            "confidence": round(confidence, 4),
            "latency_ms": round(elapsed_ms, 2),
        }

    def predict_batch(self, texts: list[str]) -> list[dict]:
        """Classify a batch of context windows."""
        start = time.perf_counter()

        enc = self.tokenizer(
            texts,
            return_tensors="np",
            padding="max_length",
            max_length=self.max_length,
            truncation=True,
        )

        outputs = self.session.run(
            None,
            {
                "input_ids": enc["input_ids"].astype(np.int64),
                "attention_mask": enc["attention_mask"].astype(np.int64),
            },
        )
        logits = outputs[0]
        elapsed_ms = (time.perf_counter() - start) * 1000

        labels_map = self.metadata.get("labels", {0: "NOT_SECRET", 1: "SECRET"})
        results = []
        for i, row in enumerate(logits):
            probs = _softmax(row)
            pred = int(np.argmax(probs))
            confidence = float(probs[pred])
            label_name = labels_map.get(str(pred), labels_map.get(pred, "UNKNOWN"))
            results.append({
                "label": pred,
                "label_name": label_name,
                "confidence": round(confidence, 4),
                "latency_ms": round(elapsed_ms / len(texts), 2),
            })
        return results

    def predict_file_line(self, filepath: str, target_line: int,
                          context_lines: int = 10) -> dict:
        """Read a file and classify the context around a specific line."""
        try:
            with open(filepath, "r", errors="replace") as fh:
                lines = fh.readlines()
        except (IOError, OSError) as exc:
            return {"error": str(exc)}

        start = max(0, target_line - 1 - context_lines)
        end = min(len(lines), target_line + context_lines)
        window = lines[start:end]

        relative = target_line - 1 - start
        if 0 <= relative < len(window):
            window[relative] = f">>> LINE {target_line} <<< " + window[relative]

        text = "".join(window).strip()
        result = self.predict(text)
        result["file"] = filepath
        result["line"] = target_line
        return result


def _softmax(logits: np.ndarray) -> np.ndarray:
    exp = np.exp(logits - np.max(logits))
    return exp / exp.sum()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MORPHEX Secret Classifier — inference"
    )
    parser.add_argument("--model", required=True,
                        help="Path to model directory (with model.onnx)")
    parser.add_argument("--text", help="Raw text to classify")
    parser.add_argument("--file", help="File path to read context from")
    parser.add_argument("--line", type=int,
                        help="Target line number (with --file)")
    parser.add_argument("--context-lines", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    classifier = SecretClassifier(args.model)

    if args.text:
        result = classifier.predict(args.text)
    elif args.file and args.line:
        result = classifier.predict_file_line(
            args.file, args.line, args.context_lines
        )
    else:
        print("Provide --text or --file + --line", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        label = result.get("label_name", "UNKNOWN")
        conf = result.get("confidence", 0)
        ms = result.get("latency_ms", 0)
        print(f"Prediction: {label}  confidence={conf:.1%}  latency={ms:.1f}ms")


if __name__ == "__main__":
    main()
