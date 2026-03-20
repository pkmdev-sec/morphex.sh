#!/usr/bin/env python3
"""
MORPHEX Contextual Secret Classifier — DistilBERT Fine-Tuning

Fine-tunes distilbert-base-uncased on code-context windows to classify
whether a highlighted line contains a real secret (1) or not (0).

Input:   JSONL file from prepare_dataset.py  ({"text": ..., "label": 0|1})
Output:  PyTorch model  +  ONNX export  +  tokenizer files

Usage:
    python train.py \
        --data       ../models/train.jsonl \
        --output-dir ../models/distilbert-secret-classifier \
        --epochs 5 \
        --batch-size 16 \
        --lr 2e-5

Requirements:
    pip install torch transformers datasets scikit-learn onnx onnxruntime
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    get_linear_schedule_with_warmup,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    classification_report,
)


MAX_LENGTH = 512
MODEL_NAME = "distilbert-base-uncased"


class SecretDataset(Dataset):
    """Tokenized dataset for secret classification."""

    def __init__(self, texts: list[str], labels: list[int],
                 tokenizer: DistilBertTokenizerFast,
                 max_length: int = MAX_LENGTH):
        self.encodings = tokenizer(
            texts,
            truncation=True,
            padding="max_length",
            max_length=max_length,
            return_tensors="pt",
        )
        self.labels = torch.tensor(labels, dtype=torch.long)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> dict:
        return {
            "input_ids": self.encodings["input_ids"][idx],
            "attention_mask": self.encodings["attention_mask"][idx],
            "labels": self.labels[idx],
        }


def load_jsonl(path: str) -> tuple[list[str], list[int]]:
    """Load JSONL dataset into parallel text/label lists."""
    texts, labels = [], []
    with open(path) as fh:
        for line in fh:
            row = json.loads(line)
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def evaluate(model, dataloader, device) -> dict:
    """Run evaluation and return metric dict."""
    model.eval()
    all_preds, all_labels = [], []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            preds = torch.argmax(outputs.logits, dim=-1)

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    return {
        "accuracy": accuracy_score(all_labels, all_preds),
        "precision": precision_score(all_labels, all_preds, zero_division=0),
        "recall": recall_score(all_labels, all_preds, zero_division=0),
        "f1": f1_score(all_labels, all_preds, zero_division=0),
        "report": classification_report(
            all_labels, all_preds,
            target_names=["NOT_SECRET", "SECRET"],
            zero_division=0,
        ),
    }


def export_onnx(model, tokenizer, output_dir: str, max_length: int) -> str:
    """Export the trained model to ONNX format."""
    model.eval()
    model.cpu()

    dummy_input = tokenizer(
        "dummy input for tracing",
        return_tensors="pt",
        padding="max_length",
        max_length=max_length,
        truncation=True,
    )

    onnx_path = os.path.join(output_dir, "model.onnx")

    torch.onnx.export(
        model,
        (dummy_input["input_ids"], dummy_input["attention_mask"]),
        onnx_path,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
        do_constant_folding=True,
    )

    print(f"ONNX model exported to {onnx_path}")
    size_mb = os.path.getsize(onnx_path) / (1024 * 1024)
    print(f"ONNX model size: {size_mb:.1f} MB")
    return onnx_path


def verify_onnx(onnx_path: str, tokenizer, sample_text: str,
                max_length: int) -> None:
    """Quick sanity check: run inference with ONNX Runtime."""
    try:
        import onnxruntime as ort
    except ImportError:
        print("onnxruntime not installed — skipping ONNX verification")
        return

    session = ort.InferenceSession(onnx_path)
    enc = tokenizer(
        sample_text,
        return_tensors="np",
        padding="max_length",
        max_length=max_length,
        truncation=True,
    )

    outputs = session.run(
        None,
        {
            "input_ids": enc["input_ids"].astype(np.int64),
            "attention_mask": enc["attention_mask"].astype(np.int64),
        },
    )
    logits = outputs[0]
    pred = int(np.argmax(logits, axis=-1)[0])
    probs = np.exp(logits[0]) / np.sum(np.exp(logits[0]))
    print(f"ONNX verification — pred={pred}, probs={probs}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the MORPHEX contextual secret classifier"
    )
    parser.add_argument("--data", required=True, help="JSONL training data")
    parser.add_argument("--output-dir", required=True, help="Model output dir")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=MAX_LENGTH)
    parser.add_argument("--val-split", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-onnx", action="store_true",
                        help="Skip ONNX export")
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    # ── Load data ───────────────────────────────────────────────────────
    texts, labels = load_jsonl(args.data)
    print(f"Loaded {len(texts)} samples "
          f"({sum(labels)} positive, {len(labels) - sum(labels)} negative)")

    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels,
        test_size=args.val_split,
        random_state=args.seed,
        stratify=labels,
    )
    print(f"Train: {len(train_texts)}  Val: {len(val_texts)}")

    # Compute class weights to handle imbalanced data (e.g., 1:11 pos:neg ratio).
    # This ensures the model doesn't just predict the majority class.
    num_pos = sum(train_labels)
    num_neg = len(train_labels) - num_pos
    if num_pos > 0 and num_neg > 0:
        weight_neg = len(train_labels) / (2.0 * num_neg)
        weight_pos = len(train_labels) / (2.0 * num_pos)
        class_weights = torch.tensor([weight_neg, weight_pos], dtype=torch.float32).to(device)
        print(f"Class weights: NOT_SECRET={weight_neg:.3f}, SECRET={weight_pos:.3f}")
    else:
        class_weights = None

    # ── Tokenizer + datasets ────────────────────────────────────────────
    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)

    train_ds = SecretDataset(train_texts, train_labels, tokenizer,
                             args.max_length)
    val_ds = SecretDataset(val_texts, val_labels, tokenizer, args.max_length)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size,
                              shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)

    # ── Model ───────────────────────────────────────────────────────────
    model = DistilBertForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=2
    )
    model.to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr,
                                  weight_decay=0.01)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(0.1 * total_steps),
        num_training_steps=total_steps,
    )

    # ── Training loop ───────────────────────────────────────────────────
    best_f1 = 0.0
    os.makedirs(args.output_dir, exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0

        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            batch_labels = batch["labels"].to(device)

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            )
            # Use class-weighted cross-entropy to handle label imbalance.
            if class_weights is not None:
                loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)
            else:
                loss_fn = torch.nn.CrossEntropyLoss()
            loss = loss_fn(outputs.logits, batch_labels)
            total_loss += loss.item()

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            if step % 10 == 0:
                print(f"  Epoch {epoch} step {step}/{len(train_loader)} "
                      f"loss={loss.item():.4f}")

        avg_loss = total_loss / len(train_loader)

        # ── Validation ──────────────────────────────────────────────────
        metrics = evaluate(model, val_loader, device)
        print(f"\nEpoch {epoch}/{args.epochs}  "
              f"loss={avg_loss:.4f}  "
              f"val_acc={metrics['accuracy']:.3f}  "
              f"val_prec={metrics['precision']:.3f}  "
              f"val_rec={metrics['recall']:.3f}  "
              f"val_f1={metrics['f1']:.3f}")

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            model.save_pretrained(args.output_dir)
            tokenizer.save_pretrained(args.output_dir)
            print(f"  ✓ Saved best model (F1={best_f1:.3f})")

    # ── Final evaluation ────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("Final evaluation on validation set:")
    print("=" * 60)
    best_model = DistilBertForSequenceClassification.from_pretrained(
        args.output_dir
    ).to(device)
    final_metrics = evaluate(best_model, val_loader, device)
    print(final_metrics["report"])

    # ── ONNX export ─────────────────────────────────────────────────────
    if not args.no_onnx:
        print("\nExporting to ONNX...")
        onnx_path = export_onnx(best_model, tokenizer, args.output_dir,
                                args.max_length)
        if val_texts:
            verify_onnx(onnx_path, tokenizer, val_texts[0], args.max_length)

    # ── Save metadata ───────────────────────────────────────────────────
    meta = {
        "model_name": MODEL_NAME,
        "max_length": args.max_length,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "lr": args.lr,
        "train_samples": len(train_texts),
        "val_samples": len(val_texts),
        "best_val_f1": round(best_f1, 4),
        "final_metrics": {
            k: round(v, 4) if isinstance(v, float) else v
            for k, v in final_metrics.items()
            if k != "report"
        },
        "labels": {0: "NOT_SECRET", 1: "SECRET"},
    }
    meta_path = os.path.join(args.output_dir, "training_metadata.json")
    with open(meta_path, "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"\nMetadata saved to {meta_path}")
    print(f"Best F1: {best_f1:.4f}")


if __name__ == "__main__":
    main()
