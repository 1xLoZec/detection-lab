#!/usr/bin/env python3
"""
Tall Kitchen — review-gate approval CLI.

Water (with WATER_REVIEW_GATE=true) holds validated rules in state/pending_rules.json
and the Sigma yaml in detections/pending/ instead of deploying. This tool lets a human
review and approve/reject them. Approving runs the SAME save_and_push the normal path uses,
so an approved rule deploys exactly as before — just with a human in the loop.

Usage:
  python3 approve.py list                 # show pending rules
  python3 approve.py show <rule_id>       # print the full sigma yaml
  python3 approve.py approve <rule_id>    # deploy it (save_and_push + git)
  python3 approve.py reject <rule_id>     # discard it
"""
import sys, json
from pathlib import Path
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
STATE = HERE / "state" / "pending_rules.json"
PENDING_DIR = HERE / "detections" / "pending"

def _load():
    try: return json.loads(STATE.read_text())
    except Exception: return []

def _save(items):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(items, indent=2))

def cmd_list():
    items = _load()
    if not items:
        print("No rules pending review."); return
    print(f"\n  {len(items)} rule(s) pending review:\n")
    for it in items:
        print(f"  {it['rule_id'][:8]}  {it['technique_id']:<12} {it['technique_name']}")
        print(f"            confidence: {it.get('confidence','?')}   queued: {it.get('queued_at','?')[:16]}")
    print("\n  approve:  python3 approve.py approve <rule_id>")
    print("  show:     python3 approve.py show <rule_id>\n")

def _find(prefix):
    items = _load()
    matches = [it for it in items if it["rule_id"].startswith(prefix)]
    if not matches:
        print(f"No pending rule matching '{prefix}'"); sys.exit(1)
    if len(matches) > 1:
        print(f"Ambiguous '{prefix}' — matches {len(matches)} rules; use more characters"); sys.exit(1)
    return matches[0]

def cmd_show(prefix):
    it = _find(prefix)
    y = (PENDING_DIR / f"{it['rule_id']}.yml")
    print(f"\n  {it['technique_id']} — {it['technique_name']}")
    print(f"  confidence: {it.get('confidence')}   queued: {it.get('queued_at')}\n")
    print(y.read_text() if y.exists() else "(yaml file missing)")

def cmd_approve(prefix):
    it = _find(prefix)
    y = PENDING_DIR / f"{it['rule_id']}.yml"
    if not y.exists():
        print("yaml file missing, cannot deploy"); sys.exit(1)
    sigma_yaml = y.read_text()
    # reuse Water's real deploy path
    from generate_rule import save_and_push, load_state, save_state, git_push_state
    analysis = {"technique_id": it["technique_id"], "technique_name": it["technique_name"],
                "tactic": it.get("tactic"), "confidence": it.get("confidence")}
    filepath = save_and_push(sigma_yaml, analysis, it["rule_id"])
    print(f"  ✓ approved + deployed: {it['technique_id']} {it['technique_name']}")
    print(f"    {filepath}")
    # update state: add to seen + log, remove from pending
    seen, last, log, digest = load_state()
    now = datetime.now(timezone.utc).isoformat()
    seen[it["technique_id"]] = {"technique_name": it["technique_name"], "tactic": it.get("tactic"),
                                "rule_id": it["rule_id"], "deployed_at": now, "confidence": it.get("confidence")}
    log.append({"timestamp": now, "result": "deployed", "technique_id": it["technique_id"],
                "technique_name": it["technique_name"], "confidence": it.get("confidence"),
                "rule_id": it["rule_id"], "filepath": filepath, "approved_by": "human"})
    save_state(seen, last, log, digest)
    git_push_state()
    items = [x for x in _load() if x["rule_id"] != it["rule_id"]]
    _save(items)
    y.unlink(missing_ok=True)
    print("    pending queue updated.")

def cmd_reject(prefix):
    it = _find(prefix)
    items = [x for x in _load() if x["rule_id"] != it["rule_id"]]
    _save(items)
    (PENDING_DIR / f"{it['rule_id']}.yml").unlink(missing_ok=True)
    print(f"  ✗ rejected + discarded: {it['technique_id']} {it['technique_name']}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(0)
    cmd = sys.argv[1]
    if cmd == "list": cmd_list()
    elif cmd == "show" and len(sys.argv) > 2: cmd_show(sys.argv[2])
    elif cmd == "approve" and len(sys.argv) > 2: cmd_approve(sys.argv[2])
    elif cmd == "reject" and len(sys.argv) > 2: cmd_reject(sys.argv[2])
    else: print(__doc__)
