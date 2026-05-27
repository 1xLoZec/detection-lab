"""
Tall Kitchen Hunt - web API.
Thin wrapper over tallkitchen_hunt. Imports the real logic, never duplicates it.
Serves the concise verdict + source breakdown as JSON, and the static page.
"""
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

import tallkitchen_hunt as tk

app = FastAPI(title="Tall Kitchen Hunt")

HERE = Path(__file__).resolve().parent
WEB_DIR = HERE / "web"


def _run_hunt(ioc: str) -> dict:
    ioc = (ioc or "").strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="empty IOC")
    ioc_type = tk.detect_ioc_type(ioc)
    if ioc_type not in ("ipv4", "md5", "sha1", "sha256", "domain"):
        return {"ioc": ioc, "ioc_type": ioc_type, "supported": False,
                "message": f"Unsupported IOC type: {ioc_type}. Supported: IPv4, file hash, domain."}

    conn = tk.memory_init()
    try:
        is_hash = ioc_type in ("md5", "sha1", "sha256")
        is_domain = ioc_type == "domain"
        if is_hash:
            external = tk.bucket_external_hash(conn, ioc, ioc_type)
        elif is_domain:
            external = tk.bucket_external_domain(conn, ioc)
        else:
            # IP path needs internal SIEM; degrade gracefully if unreachable
            try:
                external = tk.bucket_external_ip(conn, ioc)
            except Exception as e:
                external = {}
        verdict = tk.bucket_verdict({}, external, ioc_type)
    finally:
        conn.close()

    return {"ioc": ioc, "ioc_type": ioc_type, "supported": True,
            "verdict": verdict, "external": external}


@app.get("/api/hunt")
def api_hunt(ioc: str):
    return JSONResponse(_run_hunt(ioc))


# ── Water dashboard data ──────────────────────────────────────────────────────
# Reads Water's real state files. No invented data.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


@app.get("/api/water")
def api_water():
    state = HERE / "state"
    seen, log, last_run = {}, [], None
    try:
        seen = json.loads((state / "seen_techniques.json").read_text())
    except Exception:
        seen = {}
    try:
        log = json.loads((state / "hunt_log.json").read_text())
    except Exception:
        log = []
    try:
        last_run = json.loads((state / "last_run.json").read_text()).get("timestamp")
    except Exception:
        last_run = None
    # rule efficacy snapshot (real fires per deployed rule; updated when rule_efficacy.py runs)
    efficacy = None
    try:
        eff = json.loads((state / "rule_efficacy.json").read_text())
        fired = []
        for tid, r in (eff.get("by_technique") or {}).items():
            if isinstance(r, dict) and r.get("fire_count", 0) > 0:
                fired.append({
                    "id": tid,
                    "name": r.get("technique_name"),
                    "count": r.get("fire_count", 0),
                    "last_fired": r.get("last_fired"),
                })
        fired.sort(key=lambda x: x["count"], reverse=True)
        efficacy = {
            "measured_at": eff.get("generated_at"),
            "total_rules": eff.get("total_rules", 0),
            "rules_fired": eff.get("rules_fired", 0),
            "rules_dormant": eff.get("rules_dormant", 0),
            "fired": fired,
        }
    except Exception:
        efficacy = None

    # techniques grouped by tactic
    by_tactic = {}
    for tid, t in seen.items():
        tac = (t.get("tactic") or "unknown")
        by_tactic.setdefault(tac, []).append({
            "id": tid,
            "name": t.get("technique_name"),
            "confidence": t.get("confidence"),
            "deployed_at": t.get("deployed_at"),
        })
    for tac in by_tactic:
        by_tactic[tac].sort(key=lambda x: x["id"])

    # outcome + confidence counts from the log
    outcomes, confidences = {}, {}
    for e in log:
        outcomes[e.get("result", "unknown")] = outcomes.get(e.get("result", "unknown"), 0) + 1
        c = e.get("confidence")
        if c:
            confidences[c] = confidences.get(c, 0) + 1

    # count rule files actually on disk
    sigma_dir = HERE / "detections" / "sigma"
    prod_rules = len(list(sigma_dir.glob("*.yml"))) if sigma_dir.exists() else 0
    ht_dir = sigma_dir / "hunt-triggered"
    hunt_triggered = len(list(ht_dir.glob("*.yml"))) if ht_dir.exists() else 0

    # newest-first timeline (cap to 60)
    timeline = sorted(log, key=lambda e: e.get("timestamp") or "", reverse=True)[:60]

    return JSONResponse({
        "last_run": last_run,
        "techniques_covered": len(seen),
        "tactic_order": TACTIC_ORDER,
        "by_tactic": by_tactic,
        "outcomes": outcomes,
        "confidences": confidences,
        "prod_rules": prod_rules,
        "hunt_triggered": hunt_triggered,
        "timeline": timeline,
        "efficacy": efficacy,
    })


@app.get("/water")
def water_page():
    return FileResponse(WEB_DIR / "water.html")


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
