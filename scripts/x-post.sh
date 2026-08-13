#!/usr/bin/env bash
# Post an X update for the Telegraph hackathon.
# Usage: x-post.sh <file-with-post-text>
# Prefers xurl (if authenticated); otherwise logs a manual-post reminder.
set -uo pipefail

FILE="${1:-}"
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "ERROR: pass a file containing the post text" >&2
  exit 1
fi

TEXT="$(cat "$FILE")"
TS="$(date -u '+%Y-%m-%d %H:%M UTC')"
LOG="/root/work/vulnfeed/docs/x-posts/post-log.txt"

# Tag check — every judging post must tag @Telegraphprotoc
if ! grep -q "@Telegraphprotoc" "$FILE"; then
  echo "WARNING: post does not tag @Telegraphprotoc (required for judging)" >&2
fi

if command -v xurl >/dev/null 2>&1 && xurl whoami >/dev/null 2>&1; then
  echo "[$TS] posting via xurl..." | tee -a "$LOG"
  if OUT=$(xurl post "$TEXT" 2>&1); then
    echo "[$TS] POSTED OK: $(echo "$OUT" | head -c 200)" | tee -a "$LOG"
    echo "$OUT"
    exit 0
  else
    echo "[$TS] xurl FAILED: $OUT" | tee -a "$LOG"
    exit 1
  fi
else
  echo "[$TS] xurl not ready — POST MANUALLY from $FILE :" | tee -a "$LOG"
  echo "---" | tee -a "$LOG"
  cat "$FILE" | tee -a "$LOG"
  echo "---" | tee -a "$LOG"
  exit 2
fi
