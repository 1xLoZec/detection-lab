#!/bin/bash
# Tall Kitchen — scheduled Water run WITH the review gate ON.
# Generates + validates rules, HOLDS them for human approval (approve.py), emails the analyst.
# Never auto-deploys. Approval is always a human step.

PROJ="/Users/albundy/detection-lab"
LOG="/tmp/tk_water.log"
PY="$PROJ/venv/bin/python3"

echo "===== $(date '+%Y-%m-%d %H:%M:%S') water run (gated) =====" >> "$LOG"

# bring WireGuard up if needed (Water queries ELK at 10.0.0.1)
if ! scutil --nc status "wg0-client" 2>/dev/null | head -1 | grep -q "Connected"; then
  echo "WG not connected, starting..." >> "$LOG"
  scutil --nc start "wg0-client" >> "$LOG" 2>&1
  sleep 6
fi

if ! ping -c1 -W2 10.0.0.1 >/dev/null 2>&1; then
  echo "ELK NOT reachable, skipping this run" >> "$LOG"
  exit 0
fi

cd "$PROJ" || { echo "cd failed" >> "$LOG"; exit 1; }
# the gate flag is the whole point: validated rules are HELD, not deployed
WATER_REVIEW_GATE=true "$PY" generate_rule.py >> "$LOG" 2>&1
echo "exit code: $?" >> "$LOG"
