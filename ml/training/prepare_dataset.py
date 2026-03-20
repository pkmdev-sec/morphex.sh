#!/usr/bin/env python3
"""
Unified dataset preparation for the MORPHEX contextual secret classifier.

Merges three labeled data sources into a single JSONL training set:

  1. morphex-benchmark     — 102 hand-labeled files (ground_truth.json, per-line)
  2. synapse/benchmark   — 49 TP + 12 TN corpus files (ground_truth.json)
  3. synapse/scale       — 10K synthetic files, 300 secrets + 1700 FP traps

Each sample is a ±N-line context window around a candidate string, labeled:
  {"text": "<context window>", "label": 1}   # true secret
  {"text": "<context window>", "label": 0}   # not a secret

Usage:
    python prepare_dataset.py --base-dir ../../.. --output ../models/train.jsonl

    Alternatively, point at each source individually:
    python prepare_dataset.py \
        --morphex-dataset  ../../../morphex-benchmark/dataset \
        --morphex-gt       ../../../morphex-benchmark/labels/ground_truth.json \
        --synapse-corpus ../../../synapse/benchmark/corpus \
        --synapse-gt     ../../../synapse/benchmark/ground_truth.json \
        --scale-corpus   ../../../synapse/benchmark/scale/corpus \
        --scale-gt       ../../../synapse/benchmark/scale/ground_truth.json \
        --output         ../models/train.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from pathlib import Path
from typing import List, Dict, Optional

CONTEXT_LINES = 10

# Regex patterns that identify lines containing potential secret candidates.
EXTRACT_PATTERNS = [
    re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["\']([^"\']{8,})["\']'),
    re.compile(r'export\s+([A-Z_][A-Z0-9_]*)\s*=\s*(\S{8,})'),
    re.compile(r'^([A-Z_][A-Z0-9_]*)\s*=\s*([^\s#]{8,})', re.MULTILINE),
    re.compile(r'"([A-Za-z_]\w*)"\s*:\s*"([^"]{8,})"'),
    re.compile(r'(-----BEGIN\s+\w[\w ]*PRIVATE\s+KEY-----)'),
    re.compile(r'((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://\S+)'),
    re.compile(r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9_-]{36,})'),
    re.compile(r'(Server=[^;]+;.*Password=[^;]+)'),
]


# ─── Helpers ──────────────────────────────────────────────────────────────

def read_context_window(filepath: str, target_line: int,
                        ctx: int = CONTEXT_LINES) -> str:
    """Return ±ctx lines around target_line (1-based), with a marker."""
    try:
        with open(filepath, "r", errors="replace") as fh:
            lines = fh.readlines()
    except (IOError, OSError):
        return ""
    start = max(0, target_line - 1 - ctx)
    end = min(len(lines), target_line + ctx)
    window = list(lines[start:end])
    rel = target_line - 1 - start
    if 0 <= rel < len(window):
        window[rel] = f">>> LINE {target_line} <<< " + window[rel]
    return "".join(window).strip()


def extract_candidate_lines(filepath: str) -> List[int]:
    """Return 1-based line numbers with regex-matched candidate strings."""
    try:
        with open(filepath, "r", errors="replace") as fh:
            file_lines = fh.readlines()
    except (IOError, OSError):
        return []
    hits: List[int] = []
    for idx, line in enumerate(file_lines):
        for pat in EXTRACT_PATTERNS:
            if pat.search(line):
                hits.append(idx + 1)
                break
    return hits


# ─── Source 1: morphex-benchmark ────────────────────────────────────────────

def load_morphex_benchmark(dataset_dir: str, gt_path: str,
                         ctx: int) -> List[dict]:
    """Load morphex-benchmark with per-line ground truth."""
    if not os.path.isdir(dataset_dir) or not os.path.isfile(gt_path):
        return []

    with open(gt_path) as fh:
        gt = json.load(fh)

    # Build {rel_path: {line: is_real_secret}}
    gt_index: Dict[str, Dict[int, bool]] = {}
    for entry in gt.get("files", []):
        raw = entry["path"]
        rel = raw.replace("dataset/", "", 1) if raw.startswith("dataset/") else raw
        secrets = {}
        for sec in entry.get("secrets", []):
            secrets[sec["line"]] = sec["is_real_secret"]
        gt_index[rel] = secrets

    dataset_path = Path(dataset_dir)
    samples: List[dict] = []

    for root, dirs, files in os.walk(dataset_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
        for fname in files:
            full = os.path.join(root, fname)
            rel = str(Path(full).relative_to(dataset_path))
            gt_entry = gt_index.get(rel, {})
            candidate_lines = extract_candidate_lines(full)

            for line_num in candidate_lines:
                window = read_context_window(full, line_num, ctx)
                if not window:
                    continue
                if line_num in gt_entry:
                    label = 1 if gt_entry[line_num] else 0
                else:
                    # Infer from directory placement
                    if "false-positives/" in rel:
                        label = 0
                    elif "true-positives/" in rel and any(gt_entry.values()):
                        label = 1
                    else:
                        label = 0
                samples.append({
                    "text": window, "label": label,
                    "source": "morphex-benchmark", "file": rel, "line": line_num,
                })

    return samples


# ─── Source 2: synapse/benchmark/corpus ───────────────────────────────────

def load_synapse_corpus(corpus_dir: str, gt_path: str,
                        ctx: int) -> List[dict]:
    """Load the SYNAPSE benchmark corpus with TP/TN ground truth."""
    if not os.path.isdir(corpus_dir) or not os.path.isfile(gt_path):
        return []

    with open(gt_path) as fh:
        gt = json.load(fh)

    samples: List[dict] = []

    # True positives have per-line labels
    tp_lines: Dict[str, set] = {}
    for entry in gt.get("true_positives", []):
        fname = entry["file"]
        # Normalise: "corpus/tp_aws_keys.py" -> resolve from corpus_dir parent
        tp_lines.setdefault(fname, set())
        if "line" in entry:
            tp_lines[fname].add(entry["line"])

    # True negatives are entire files
    tn_files = set()
    for entry in gt.get("true_negatives", []):
        tn_files.add(entry["file"])

    corpus_root = Path(corpus_dir)
    parent = corpus_root.parent  # synapse/benchmark

    # Process TPs
    for fname, known_lines in tp_lines.items():
        full = str(parent / fname)
        if not os.path.isfile(full):
            continue
        lines_to_process = known_lines if known_lines else set(extract_candidate_lines(full))
        for line_num in lines_to_process:
            window = read_context_window(full, line_num, ctx)
            if window:
                samples.append({
                    "text": window, "label": 1,
                    "source": "synapse-corpus", "file": fname, "line": line_num,
                })

    # Process TNs — every candidate line is a negative
    for entry in gt.get("true_negatives", []):
        fname = entry["file"]
        full = str(parent / fname)
        if not os.path.isfile(full):
            continue
        for line_num in extract_candidate_lines(full):
            window = read_context_window(full, line_num, ctx)
            if window:
                samples.append({
                    "text": window, "label": 0,
                    "source": "synapse-corpus", "file": fname, "line": line_num,
                })

    return samples


# ─── Source 3: synapse/benchmark/scale ────────────────────────────────────

def load_scale_corpus(corpus_dir: str, gt_path: str,
                      ctx: int, max_negatives: int = 5000) -> List[dict]:
    """Load the 10K-file scale corpus. Secrets and FP traps are labeled;
    we also sample random candidate lines from TN files as extra negatives."""
    if not os.path.isdir(corpus_dir) or not os.path.isfile(gt_path):
        return []

    with open(gt_path) as fh:
        gt = json.load(fh)

    samples: List[dict] = []

    # Labeled secrets (TP)
    for entry in gt.get("secrets", []):
        full = os.path.join(corpus_dir, entry["file"])
        full = os.path.normpath(full)
        if not os.path.isfile(full):
            # Try from corpus_dir directly
            full = os.path.join(corpus_dir, os.path.basename(entry["file"]))
            if not os.path.isfile(full):
                continue
        window = read_context_window(full, entry["line"], ctx)
        if window:
            samples.append({
                "text": window, "label": 1,
                "source": "scale", "file": entry["file"], "line": entry["line"],
            })

    # Labeled FP traps (TN)
    for entry in gt.get("fp_traps", []):
        full = os.path.join(corpus_dir, entry["file"])
        full = os.path.normpath(full)
        if not os.path.isfile(full):
            full = os.path.join(corpus_dir, os.path.basename(entry["file"]))
            if not os.path.isfile(full):
                continue
        line = entry.get("line", 1)
        window = read_context_window(full, line, ctx)
        if window:
            samples.append({
                "text": window, "label": 0,
                "source": "scale", "file": entry["file"], "line": line,
            })

    # Extra negatives: sample candidate lines from TN files
    tn_files = gt.get("tn_files", [])
    if tn_files and max_negatives > 0:
        random.shuffle(tn_files)
        extra_neg = 0
        for fname in tn_files:
            if extra_neg >= max_negatives:
                break
            full = os.path.join(corpus_dir, fname)
            full = os.path.normpath(full)
            if not os.path.isfile(full):
                continue
            candidates = extract_candidate_lines(full)
            for line_num in candidates[:3]:  # cap per file
                window = read_context_window(full, line_num, ctx)
                if window:
                    samples.append({
                        "text": window, "label": 0,
                        "source": "scale-tn", "file": fname, "line": line_num,
                    })
                    extra_neg += 1
                    if extra_neg >= max_negatives:
                        break

    return samples


# ─── Main ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare unified training dataset from all labeled sources"
    )
    parser.add_argument("--base-dir",
                        help="Root of the project (contains morphex-benchmark/ and synapse/)")
    parser.add_argument("--morphex-dataset", help="Path to morphex-benchmark/dataset")
    parser.add_argument("--morphex-gt", help="Path to morphex-benchmark/labels/ground_truth.json")
    parser.add_argument("--synapse-corpus", help="Path to synapse/benchmark/corpus")
    parser.add_argument("--synapse-gt", help="Path to synapse/benchmark/ground_truth.json")
    parser.add_argument("--scale-corpus", help="Path to synapse/benchmark/scale/corpus")
    parser.add_argument("--scale-gt", help="Path to synapse/benchmark/scale/ground_truth.json")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--context-lines", type=int, default=CONTEXT_LINES)
    parser.add_argument("--max-scale-negatives", type=int, default=5000,
                        help="Cap on extra negatives from scale TN files")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)

    # Resolve paths from --base-dir if individual paths not given
    base = args.base_dir or ""
    morphex_dataset = args.morphex_dataset or os.path.join(base, "morphex-benchmark", "dataset")
    morphex_gt = args.morphex_gt or os.path.join(base, "morphex-benchmark", "labels", "ground_truth.json")
    synapse_corpus = args.synapse_corpus or os.path.join(base, "synapse", "benchmark", "corpus")
    synapse_gt = args.synapse_gt or os.path.join(base, "synapse", "benchmark", "ground_truth.json")
    scale_corpus = args.scale_corpus or os.path.join(base, "synapse", "benchmark", "scale", "corpus")
    scale_gt = args.scale_gt or os.path.join(base, "synapse", "benchmark", "scale", "ground_truth.json")
    ctx = args.context_lines

    all_samples: List[dict] = []

    # Source 1
    s1 = load_morphex_benchmark(morphex_dataset, morphex_gt, ctx)
    print(f"[morphex-benchmark]  {len(s1)} samples "
          f"({sum(1 for s in s1 if s['label']==1)} pos, "
          f"{sum(1 for s in s1 if s['label']==0)} neg)")
    all_samples.extend(s1)

    # Source 2
    s2 = load_synapse_corpus(synapse_corpus, synapse_gt, ctx)
    print(f"[synapse-corpus]   {len(s2)} samples "
          f"({sum(1 for s in s2 if s['label']==1)} pos, "
          f"{sum(1 for s in s2 if s['label']==0)} neg)")
    all_samples.extend(s2)

    # Source 3
    s3 = load_scale_corpus(scale_corpus, scale_gt, ctx, args.max_scale_negatives)
    print(f"[scale-corpus]     {len(s3)} samples "
          f"({sum(1 for s in s3 if s['label']==1)} pos, "
          f"{sum(1 for s in s3 if s['label']==0)} neg)")
    all_samples.extend(s3)

    # Deduplicate by (file, line, source)
    seen = set()
    deduped = []
    for s in all_samples:
        key = (s.get("source", ""), s.get("file", ""), s.get("line", 0))
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    all_samples = deduped

    # Shuffle
    random.shuffle(all_samples)

    positives = sum(1 for s in all_samples if s["label"] == 1)
    negatives = len(all_samples) - positives
    print(f"\n{'='*60}")
    print(f"TOTAL: {len(all_samples)} samples — {positives} positive, {negatives} negative")
    if positives > 0:
        print(f"Ratio: 1:{negatives/positives:.1f} (pos:neg)")
    print(f"{'='*60}")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as fh:
        for sample in all_samples:
            fh.write(json.dumps(sample) + "\n")

    print(f"\nWritten to {args.output}")


if __name__ == "__main__":
    main()
