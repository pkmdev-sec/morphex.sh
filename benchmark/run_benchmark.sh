#!/bin/bash
###############################################################################
# AEGIS Benchmark Suite — Parallel Multi-Tool Secret Scanner Comparison
#
# Runs AEGIS, TruffleHog, and Gitleaks against every repo in test-repos/
# simultaneously, collecting structured JSON metrics per (tool, repo) pair.
#
# Usage:  ./benchmark-results/run_benchmark.sh [--timeout 120] [--category crypto]
#
# Output:
#   benchmark-results/raw/<tool>/<category>__<repo>.json   — raw tool output
#   benchmark-results/per-repo/<category>__<repo>.json     — metrics for all tools
#   benchmark-results/summaries/master.json                — full comparison
#   benchmark-results/summaries/master.csv                 — CSV for spreadsheets
###############################################################################
set -uo pipefail

# ── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PARENT_DIR="$(dirname "$PROJECT_DIR")"
TEST_REPOS="$PROJECT_DIR/test-repos"
RAW_DIR="$SCRIPT_DIR/raw"
PER_REPO_DIR="$SCRIPT_DIR/per-repo"
SUMMARY_DIR="$SCRIPT_DIR/summaries"

AEGIS_BIN="$PROJECT_DIR/src/integrations/synapse/aegis"
DETECT_SECRETS="$PARENT_DIR/aegis-benchmark/.venv/bin/detect-secrets"

# ── Config ──────────────────────────────────────────────────────────────────
TIMEOUT=180           # seconds per tool per repo
FILTER_CATEGORY=""    # empty = all
AEGIS_MODE="default"  # default | raw | verify

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)    TIMEOUT="$2"; shift 2 ;;
        --category)   FILTER_CATEGORY="$2"; shift 2 ;;
        --aegis-mode) AEGIS_MODE="$2"; shift 2 ;;
        *)            echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Setup ───────────────────────────────────────────────────────────────────
mkdir -p "$RAW_DIR"/{aegis,trufflehog,gitleaks} "$PER_REPO_DIR" "$SUMMARY_DIR"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

# Tool availability check
check_tool() {
    local name="$1" cmd="$2"
    if command -v "$cmd" &>/dev/null || [ -x "$cmd" ]; then
        printf "  ${GREEN}%-18s${NC} %s\n" "$name" "$(command -v "$cmd" 2>/dev/null || echo "$cmd")"
        return 0
    else
        printf "  ${RED}%-18s${NC} NOT FOUND\n" "$name"
        return 1
    fi
}

echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       AEGIS Benchmark Suite — Multi-Tool Comparison         ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${BOLD}AEGIS mode:${NC} $AEGIS_MODE"
case "$AEGIS_MODE" in
    raw)     echo -e "  ${DIM}(all candidates, threshold 0.3 — benchmark comparison mode)${NC}" ;;
    *)       echo -e "  ${DIM}(confirmed true positives only, threshold 0.7)${NC}" ;;
esac
echo ""
echo -e "${BOLD}Tools:${NC}"
HAS_AEGIS=0; HAS_TRUFFLEHOG=0; HAS_GITLEAKS=0
check_tool "AEGIS"       "$AEGIS_BIN"    && HAS_AEGIS=1
check_tool "TruffleHog"  "trufflehog"    && HAS_TRUFFLEHOG=1
check_tool "Gitleaks"    "gitleaks"      && HAS_GITLEAKS=1
echo ""

# ── Enumerate repos ────────────────────────────────────────────────────────
declare -a REPOS=()
for category_dir in "$TEST_REPOS"/*/; do
    category="$(basename "$category_dir")"
    [[ -n "$FILTER_CATEGORY" && "$category" != "$FILTER_CATEGORY" ]] && continue
    for repo_dir in "$category_dir"/*/; do
        [ -d "$repo_dir" ] || continue
        REPOS+=("$category|$(basename "$repo_dir")|$repo_dir")
    done
done

TOTAL_REPOS=${#REPOS[@]}
echo -e "${BOLD}Repos:${NC} $TOTAL_REPOS across $(ls -d "$TEST_REPOS"/*/ 2>/dev/null | wc -l | tr -d ' ') categories"
echo -e "${BOLD}Timeout:${NC} ${TIMEOUT}s per tool per repo"
echo -e "${BOLD}Output:${NC} $SCRIPT_DIR/"
echo ""

# ── Run single tool on single repo ─────────────────────────────────────────
# Outputs JSON: {"findings": N, "duration_s": X.XX, "peak_memory_kb": N, "exit_code": N}
run_tool() {
    local tool="$1" repo_path="$2" raw_outfile="$3"
    local start_ns end_ns duration_s findings=0 exit_code=0 peak_mem_kb=0
    local time_output="/tmp/aegis_bench_time_$$_${RANDOM}"

    start_ns=$(python3 -c "import time; print(int(time.time_ns()))")

    case "$tool" in
        aegis)
            # AEGIS scan modes:
            #   default:  Only confirmed true positives (zero FP mode)
            #   raw:      All candidates above 0.3 threshold (old behavior, for comparison)
            local aegis_flags="--json"
            case "$AEGIS_MODE" in
                raw)     aegis_flags="$aegis_flags --raw --threshold 0.3" ;;
                *)       aegis_flags="$aegis_flags --threshold 0.7" ;;
            esac
            /usr/bin/time -l timeout "$TIMEOUT" "$AEGIS_BIN" scan $aegis_flags "$repo_path" \
                > "$raw_outfile" 2>"$time_output" || exit_code=$?
            ;;
        trufflehog)
            /usr/bin/time -l timeout "$TIMEOUT" trufflehog filesystem "$repo_path" \
                --json --no-update --no-verification \
                > "$raw_outfile" 2>"$time_output" || exit_code=$?
            ;;
        gitleaks)
            /usr/bin/time -l timeout "$TIMEOUT" gitleaks detect \
                --source "$repo_path" --no-git \
                --report-format json --report-path "$raw_outfile" \
                2>"$time_output" || exit_code=$?
            # gitleaks exit 1 = findings found (not error)
            [[ $exit_code -eq 1 ]] && exit_code=0
            ;;
    esac

    end_ns=$(python3 -c "import time; print(int(time.time_ns()))")
    duration_s=$(python3 -c "print(f'{($end_ns - $start_ns) / 1e9:.3f}')")

    # Parse peak memory from /usr/bin/time output
    if [ -f "$time_output" ]; then
        peak_mem_kb=$(grep "maximum resident" "$time_output" 2>/dev/null | awk '{print int($1/1024)}' || echo 0)
        [[ -z "$peak_mem_kb" || "$peak_mem_kb" == "0" ]] && peak_mem_kb=$(grep "maximum resident" "$time_output" 2>/dev/null | grep -o '[0-9]*' | head -1 || echo 0)
        # macOS reports bytes, convert to KB
        peak_mem_kb=$(( ${peak_mem_kb:-0} ))
    fi
    rm -f "$time_output"

    # Count findings
    if [ -f "$raw_outfile" ] && [ -s "$raw_outfile" ]; then
        case "$tool" in
            aegis)
                findings=$(python3 -c "
import json, sys
try:
    d = json.load(open('$raw_outfile'))
    print(d.get('total_findings', len(d.get('findings', []))))
except: print(0)
" 2>/dev/null || echo 0)
                # Also extract suppressed count for reporting
                aegis_suppressed=$(python3 -c "
import json
try:
    d = json.load(open('$raw_outfile'))
    print(d.get('suppressed_unverified', 0))
except: print(0)
" 2>/dev/null || echo 0)
                ;;
            trufflehog)
                # JSONL: one JSON object per line
                findings=$(wc -l < "$raw_outfile" 2>/dev/null | tr -d ' ')
                ;;
            gitleaks)
                findings=$(python3 -c "
import json, sys
try:
    d = json.load(open('$raw_outfile'))
    print(len(d) if isinstance(d, list) else 0)
except: print(0)
" 2>/dev/null || echo 0)
                ;;
        esac
    fi

    # timeout gives exit 124
    local timed_out="false"
    [[ $exit_code -eq 124 ]] && timed_out="true"

    echo "{\"findings\": ${findings:-0}, \"duration_s\": $duration_s, \"peak_memory_kb\": ${peak_mem_kb:-0}, \"exit_code\": $exit_code, \"timed_out\": $timed_out}"
}

# ── Main loop ───────────────────────────────────────────────────────────────
GLOBAL_START=$(date +%s)
COMPLETED=0
ALL_RESULTS="["

for entry in "${REPOS[@]}"; do
    IFS='|' read -r category repo_name repo_path <<< "$entry"
    COMPLETED=$((COMPLETED + 1))
    slug="${category}__${repo_name}"

    echo -e "${BOLD}[${COMPLETED}/${TOTAL_REPOS}]${NC} ${CYAN}${category}/${repo_name}${NC}"

    # Get repo size
    repo_size_mb=$(du -sm "$repo_path" 2>/dev/null | awk '{print $1}')

    # Run all 3 tools IN PARALLEL
    aegis_metrics=""
    trufflehog_metrics=""
    gitleaks_metrics=""

    if [[ $HAS_AEGIS -eq 1 ]]; then
        run_tool aegis "$repo_path" "$RAW_DIR/aegis/${slug}.json" > "/tmp/bench_aegis_${slug}" 2>/dev/null &
        pid_aegis=$!
    fi
    if [[ $HAS_TRUFFLEHOG -eq 1 ]]; then
        run_tool trufflehog "$repo_path" "$RAW_DIR/trufflehog/${slug}.json" > "/tmp/bench_trufflehog_${slug}" 2>/dev/null &
        pid_trufflehog=$!
    fi
    if [[ $HAS_GITLEAKS -eq 1 ]]; then
        run_tool gitleaks "$repo_path" "$RAW_DIR/gitleaks/${slug}.json" > "/tmp/bench_gitleaks_${slug}" 2>/dev/null &
        pid_gitleaks=$!
    fi

    # Wait for all
    [[ $HAS_AEGIS -eq 1 ]]      && wait $pid_aegis 2>/dev/null
    [[ $HAS_TRUFFLEHOG -eq 1 ]] && wait $pid_trufflehog 2>/dev/null
    [[ $HAS_GITLEAKS -eq 1 ]]   && wait $pid_gitleaks 2>/dev/null

    # Collect metrics
    [[ $HAS_AEGIS -eq 1 ]]      && aegis_metrics=$(cat "/tmp/bench_aegis_${slug}" 2>/dev/null || echo '{"findings":0,"duration_s":0,"peak_memory_kb":0,"exit_code":-1,"timed_out":false}')
    [[ $HAS_TRUFFLEHOG -eq 1 ]] && trufflehog_metrics=$(cat "/tmp/bench_trufflehog_${slug}" 2>/dev/null || echo '{"findings":0,"duration_s":0,"peak_memory_kb":0,"exit_code":-1,"timed_out":false}')
    [[ $HAS_GITLEAKS -eq 1 ]]   && gitleaks_metrics=$(cat "/tmp/bench_gitleaks_${slug}" 2>/dev/null || echo '{"findings":0,"duration_s":0,"peak_memory_kb":0,"exit_code":-1,"timed_out":false}')

    rm -f "/tmp/bench_aegis_${slug}" "/tmp/bench_trufflehog_${slug}" "/tmp/bench_gitleaks_${slug}"

    # Print summary line
    a_f=$(echo "$aegis_metrics" | python3 -c "import json,sys; print(json.load(sys.stdin).get('findings',0))" 2>/dev/null || echo "?")
    a_t=$(echo "$aegis_metrics" | python3 -c "import json,sys; print(f\"{json.load(sys.stdin).get('duration_s',0)}s\")" 2>/dev/null || echo "?")
    t_f=$(echo "$trufflehog_metrics" | python3 -c "import json,sys; print(json.load(sys.stdin).get('findings',0))" 2>/dev/null || echo "?")
    t_t=$(echo "$trufflehog_metrics" | python3 -c "import json,sys; print(f\"{json.load(sys.stdin).get('duration_s',0)}s\")" 2>/dev/null || echo "?")
    g_f=$(echo "$gitleaks_metrics" | python3 -c "import json,sys; print(json.load(sys.stdin).get('findings',0))" 2>/dev/null || echo "?")
    g_t=$(echo "$gitleaks_metrics" | python3 -c "import json,sys; print(f\"{json.load(sys.stdin).get('duration_s',0)}s\")" 2>/dev/null || echo "?")

    printf "  ${GREEN}AEGIS${NC}: %-4s (%s)  ${YELLOW}TruffleHog${NC}: %-4s (%s)  ${RED}Gitleaks${NC}: %-4s (%s)\n" \
        "$a_f" "$a_t" "$t_f" "$t_t" "$g_f" "$g_t"

    # Write per-repo JSON
    cat > "$PER_REPO_DIR/${slug}.json" <<EOJSON
{
  "category": "$category",
  "repo": "$repo_name",
  "repo_path": "$repo_path",
  "repo_size_mb": ${repo_size_mb:-0},
  "tools": {
    "aegis": ${aegis_metrics:-null},
    "trufflehog": ${trufflehog_metrics:-null},
    "gitleaks": ${gitleaks_metrics:-null}
  }
}
EOJSON

    # Accumulate for master
    [[ "$ALL_RESULTS" != "[" ]] && ALL_RESULTS="${ALL_RESULTS},"
    ALL_RESULTS="${ALL_RESULTS}
{\"category\":\"$category\",\"repo\":\"$repo_name\",\"repo_size_mb\":${repo_size_mb:-0},\"aegis\":${aegis_metrics:-null},\"trufflehog\":${trufflehog_metrics:-null},\"gitleaks\":${gitleaks_metrics:-null}}"
done

GLOBAL_END=$(date +%s)
GLOBAL_DURATION=$((GLOBAL_END - GLOBAL_START))

ALL_RESULTS="${ALL_RESULTS}
]"

# ── Write master JSON ──────────────────────────────────────────────────────
cat > "$SUMMARY_DIR/master.json" <<EOFMASTER
{
  "benchmark_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total_repos": $TOTAL_REPOS,
  "timeout_per_tool_s": $TIMEOUT,
  "total_duration_s": $GLOBAL_DURATION,
  "tool_versions": {
    "aegis": "$("$AEGIS_BIN" version 2>&1 | head -1 || echo unknown)",
    "trufflehog": "$(trufflehog --version 2>&1 || echo unknown)",
    "gitleaks": "$(gitleaks version 2>&1 || echo unknown)"
  },
  "results": $ALL_RESULTS
}
EOFMASTER

# ── Generate CSV ────────────────────────────────────────────────────────────
python3 - "$SUMMARY_DIR/master.json" "$SUMMARY_DIR/master.csv" <<'PYEOF'
import json, csv, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

rows = []
for r in data["results"]:
    row = {
        "category": r["category"],
        "repo": r["repo"],
        "repo_size_mb": r["repo_size_mb"],
    }
    for tool in ["aegis", "trufflehog", "gitleaks"]:
        t = r.get(tool) or {}
        row[f"{tool}_findings"] = t.get("findings", "N/A")
        row[f"{tool}_duration_s"] = t.get("duration_s", "N/A")
        row[f"{tool}_memory_kb"] = t.get("peak_memory_kb", "N/A")
        row[f"{tool}_timed_out"] = t.get("timed_out", "N/A")
    rows.append(row)

with open(sys.argv[2], "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

print(f"  CSV written: {sys.argv[2]}")
PYEOF

# ── Generate aggregate stats ───────────────────────────────────────────────
python3 - "$SUMMARY_DIR/master.json" "$SUMMARY_DIR/aggregate.json" <<'PYEOF2'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

tools = ["aegis", "trufflehog", "gitleaks"]
agg = {}

for tool in tools:
    findings_list = []
    duration_list = []
    memory_list = []
    timeouts = 0
    errors = 0

    for r in data["results"]:
        t = r.get(tool)
        if not t:
            continue
        findings_list.append(t.get("findings", 0))
        duration_list.append(t.get("duration_s", 0))
        memory_list.append(t.get("peak_memory_kb", 0))
        if t.get("timed_out"):
            timeouts += 1
        if t.get("exit_code", 0) not in (0, ):
            errors += 1

    n = len(findings_list) or 1
    agg[tool] = {
        "total_findings": sum(findings_list),
        "avg_findings_per_repo": round(sum(findings_list) / n, 1),
        "max_findings_single_repo": max(findings_list) if findings_list else 0,
        "total_duration_s": round(sum(duration_list), 2),
        "avg_duration_per_repo_s": round(sum(duration_list) / n, 2),
        "max_duration_single_repo_s": round(max(duration_list), 2) if duration_list else 0,
        "avg_memory_kb": round(sum(memory_list) / n) if memory_list else 0,
        "max_memory_kb": max(memory_list) if memory_list else 0,
        "timeouts": timeouts,
        "errors": errors,
        "repos_scanned": len(findings_list),
    }

# Per-category breakdown
categories = sorted(set(r["category"] for r in data["results"]))
by_category = {}
for cat in categories:
    by_category[cat] = {}
    cat_results = [r for r in data["results"] if r["category"] == cat]
    for tool in tools:
        findings = [r.get(tool, {}).get("findings", 0) for r in cat_results if r.get(tool)]
        durations = [r.get(tool, {}).get("duration_s", 0) for r in cat_results if r.get(tool)]
        n = len(findings) or 1
        by_category[cat][tool] = {
            "repos": len(findings),
            "total_findings": sum(findings),
            "avg_duration_s": round(sum(durations) / n, 2),
        }

output = {
    "aggregate": agg,
    "by_category": by_category,
    "tool_versions": data["tool_versions"],
    "total_repos": data["total_repos"],
    "total_wall_time_s": data["total_duration_s"],
}

with open(sys.argv[2], "w") as f:
    json.dump(output, f, indent=2)
print(f"  Aggregate stats: {sys.argv[2]}")
PYEOF2

# ── Print final report ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║                   BENCHMARK COMPLETE                        ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Total repos:     ${BOLD}$TOTAL_REPOS${NC}"
echo -e "  Wall-clock time: ${BOLD}${GLOBAL_DURATION}s${NC}"
echo ""

python3 - "$SUMMARY_DIR/aggregate.json" <<'PYPRINT'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)

print(f"  {'Tool':<16} {'Findings':>10} {'Avg Time':>10} {'Max Time':>10} {'Avg Mem':>10} {'Timeouts':>10}")
print(f"  {'─'*16} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*10}")

for tool in ["aegis", "trufflehog", "gitleaks"]:
    a = data["aggregate"][tool]
    print(f"  {tool:<16} {a['total_findings']:>10} {a['avg_duration_per_repo_s']:>9.2f}s {a['max_duration_single_repo_s']:>9.2f}s {a['avg_memory_kb']:>8}KB {a['timeouts']:>10}")

print()
print("  By Category:")
for cat, tools in data["by_category"].items():
    parts = []
    for t in ["aegis", "trufflehog", "gitleaks"]:
        td = tools.get(t, {})
        parts.append(f"{t}={td.get('total_findings',0)}")
    print(f"    {cat:<14} {' | '.join(parts)}")
PYPRINT

echo ""
echo -e "  ${DIM}Results:  $SUMMARY_DIR/master.json${NC}"
echo -e "  ${DIM}CSV:      $SUMMARY_DIR/master.csv${NC}"
echo -e "  ${DIM}Stats:    $SUMMARY_DIR/aggregate.json${NC}"
echo -e "  ${DIM}Raw data: $RAW_DIR/<tool>/<category>__<repo>.json${NC}"
echo ""
