#!/bin/bash
# Tall Kitchen — scheduled efficacy refresh.
# Ensures WireGuard is up, then runs rule_efficacy.py with the venv Python.
# Read-only: queries ELK, writes state/rule_efficacy.json. Safe to run on a timer.

PROJ="/Users/albundy/detection-lab"
LOG="/tmp/tk_efficacy.log"
PY="$PROJ/venv/bin/python3"

echo "===== $(date '+%Y-%m-%d %H:%M:%S') efficacy run =====" >> "$LOG"

# bring WireGuard up if it isn't (needed to reach ELK at 10.0.0.1)
if ! scutil --nc status "wg0-client" 2>/dev/null | head -1 | grep -q "Connected"; then
  echo "WG not connected, starting..." >> "$LOG"
  scutil --nc start "wg0-client" >> "$LOG" 2>&1
  sleep 6
fi

# verify ELK reachable before running
if ! ping -c1 -W2 10.0.0.1 >/dev/null 2>&1; then
  echo "ELK NOT reachable, skipping this run" >> "$LOG"
  exit 0
fi

cd "$PROJ" || { echo "cd failed" >> "$LOG"; exit 1; }
"$PY" rule_efficacy.py >> "$LOG" 2>&1
echo "exit code: $?" >> "$LOG"
