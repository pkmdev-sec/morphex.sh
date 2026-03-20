#!/usr/bin/env python3
"""
morphex: PostToolUse Hook — Token Usage Tracker
Captures token usage from every API call and writes to ~/.morphex/usage-log.jsonl
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MORPHEX_DIR = Path.home() / ".morphex"
USAGE_LOG = MORPHEX_DIR / "usage-log.jsonl"


def ensure_dir():
    MORPHEX_DIR.mkdir(parents=True, exist_ok=True)


def extract_usage(hook_data: dict) -> dict | None:
    """Extract token usage from hook event data."""
    # Look for usage info in the tool result
    result = hook_data.get("result", {})
    tool_name = hook_data.get("tool_name", "unknown")

    # Try to extract from various possible locations
    usage = result.get("usage", {})
    if not usage:
        usage = result.get("token_usage", {})
    if not usage:
        return None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "model": usage.get("model", "unknown"),
        "inputTokens": usage.get("input_tokens", 0),
        "outputTokens": usage.get("output_tokens", 0),
        "cached": usage.get("cache_read_input_tokens", 0) > 0,
        "cachedTokens": usage.get("cache_read_input_tokens", 0),
        "source": "morphex-tracker-hook",
    }


def main():
    """PostToolUse hook entry point."""
    ensure_dir()

    # Read hook event from stdin
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        hook_data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        return

    record = extract_usage(hook_data)
    if not record:
        return

    # Append to usage log
    try:
        with open(USAGE_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass

    # Output success
    print(json.dumps({"status": "tracked", "tokens": record.get("inputTokens", 0) + record.get("outputTokens", 0)}))


if __name__ == "__main__":
    main()
