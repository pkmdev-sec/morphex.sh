#!/usr/bin/env bash
#
# MORPHEX ML Classifier — End-to-End Training Pipeline
#
# Prepares data from all labeled sources, fine-tunes DistilBERT,
# exports ONNX, and deploys the model to the engine model directory.
#
# Usage:
#   ./train_pipeline.sh                      # uses defaults
#   ./train_pipeline.sh --epochs 10          # override training epochs
#   CUDA_VISIBLE_DEVICES=0 ./train_pipeline.sh   # use GPU
#
# Prerequisites:
#   pip install torch transformers datasets scikit-learn onnx onnxruntime
#
set -euo pipefail

# ─── Paths ────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TRAINING_DIR="$SCRIPT_DIR/training"
MODELS_DIR="$SCRIPT_DIR/models"
OUTPUT_MODEL_DIR="$MODELS_DIR/distilbert-secret-classifier"
TRAIN_JSONL="$MODELS_DIR/train.jsonl"

# ─── Defaults (overridable via args) ─────────────────────────────────────

EPOCHS="${EPOCHS:-5}"
BATCH_SIZE="${BATCH_SIZE:-16}"
LR="${LR:-2e-5}"
MAX_LENGTH="${MAX_LENGTH:-512}"
CONTEXT_LINES="${CONTEXT_LINES:-10}"
MAX_SCALE_NEG="${MAX_SCALE_NEG:-3000}"
SEED="${SEED:-42}"

# Parse --epochs N from command line
while [[ $# -gt 0 ]]; do
  case "$1" in
    --epochs)     EPOCHS="$2"; shift 2 ;;
    --batch-size) BATCH_SIZE="$2"; shift 2 ;;
    --lr)         LR="$2"; shift 2 ;;
    --max-length) MAX_LENGTH="$2"; shift 2 ;;
    --seed)       SEED="$2"; shift 2 ;;
    *)            echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "============================================================"
echo " MORPHEX ML Classifier Training Pipeline"
echo "============================================================"
echo "  Base dir:       $BASE_DIR"
echo "  Output model:   $OUTPUT_MODEL_DIR"
echo "  Epochs:         $EPOCHS"
echo "  Batch size:     $BATCH_SIZE"
echo "  Learning rate:  $LR"
echo "  Max length:     $MAX_LENGTH"
echo "  Seed:           $SEED"
echo "============================================================"
echo ""

mkdir -p "$MODELS_DIR"

# ─── Step 1: Prepare Dataset ─────────────────────────────────────────────

echo ">>> Step 1/4: Preparing unified training dataset..."
python3 "$TRAINING_DIR/prepare_dataset.py" \
  --base-dir "$BASE_DIR" \
  --output "$TRAIN_JSONL" \
  --context-lines "$CONTEXT_LINES" \
  --max-scale-negatives "$MAX_SCALE_NEG" \
  --seed "$SEED"

SAMPLE_COUNT=$(wc -l < "$TRAIN_JSONL" | tr -d ' ')
echo "   → $SAMPLE_COUNT samples written to $TRAIN_JSONL"
echo ""

if [[ "$SAMPLE_COUNT" -lt 50 ]]; then
  echo "ERROR: Too few samples ($SAMPLE_COUNT). Need at least 50."
  exit 1
fi

# ─── Step 2: Train DistilBERT ────────────────────────────────────────────

echo ">>> Step 2/4: Fine-tuning DistilBERT..."
python3 "$TRAINING_DIR/train.py" \
  --data "$TRAIN_JSONL" \
  --output-dir "$OUTPUT_MODEL_DIR" \
  --epochs "$EPOCHS" \
  --batch-size "$BATCH_SIZE" \
  --lr "$LR" \
  --max-length "$MAX_LENGTH" \
  --seed "$SEED"

echo ""

# ─── Step 3: Verify outputs ─────────────────────────────────────────────

echo ">>> Step 3/4: Verifying model artifacts..."
REQUIRED_FILES=("model.onnx" "vocab.txt" "training_metadata.json" "tokenizer_config.json")
MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
  if [[ -f "$OUTPUT_MODEL_DIR/$f" ]]; then
    SIZE=$(du -h "$OUTPUT_MODEL_DIR/$f" | cut -f1)
    echo "   ✓ $f ($SIZE)"
  else
    echo "   ✗ $f MISSING"
    MISSING=1
  fi
done

if [[ "$MISSING" -eq 1 ]]; then
  echo "ERROR: Some model artifacts are missing."
  exit 1
fi
echo ""

# ─── Step 4: Quick sanity inference ──────────────────────────────────────

echo ">>> Step 4/4: Running sanity check inference..."
python3 "$SCRIPT_DIR/inference/predict.py" \
  --model "$OUTPUT_MODEL_DIR" \
  --text "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'" \
  --json

echo ""
python3 "$SCRIPT_DIR/inference/predict.py" \
  --model "$OUTPUT_MODEL_DIR" \
  --text "# This is a test example placeholder value\ntest_key = 'changeme_not_a_real_secret'" \
  --json

echo ""
echo "============================================================"
echo " Pipeline complete!"
echo " Model ready at: $OUTPUT_MODEL_DIR"
echo ""
echo " To use in MORPHEX, point InitClassifier to this directory:"
echo "   engine.InitClassifier(\"$OUTPUT_MODEL_DIR\")"
echo "============================================================"
