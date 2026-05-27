"""
Tall Kitchen Hunt - web API.
Thin wrapper over tallkitchen_hunt. Imports the real logic, never duplicates it.
Serves the concise verdict + source breakdown as JSON, and the static page.
"""
import json
from fastapi import FastAPI, HTTPException, Request
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
    # 3-AI validation receipts (real per-validator votes, from validate_rule.py)
    validations = None
    try:
        vraw = json.loads((state / "rule_validations.json").read_text())
        items = []
        for rid, v in vraw.items():
            atts = v.get("attempts") or []
            items.append({
                "title": v.get("title"),
                "outcome": v.get("outcome"),
                "final_attempt": v.get("final_attempt"),
                "avg_score": v.get("avg_score"),
                "backtest_hits": v.get("backtest_hits"),
                "validated_at": v.get("validated_at"),
                "attempts": atts,
                "healed": len(atts) > 1,
            })
        items.sort(key=lambda x: x.get("validated_at") or "", reverse=True)
        validations = items[:6]
    except Exception:
        validations = None

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
        "validations": validations,
    })


def _localhost_only(request: Request):
    """These endpoints CHANGE state (deploy rules). Only allow them from localhost / the
    machine itself — never a remote caller. Safe by design: no public attack surface."""
    host = (request.client.host if request.client else "") or ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="approvals are local-only")


@app.get("/api/pending")
def api_pending():
    """List rules waiting for human approval, with their 3-AI vote receipts."""
    state = HERE / "state"
    try:
        pending = json.loads((state / "pending_rules.json").read_text())
    except Exception:
        pending = []
    try:
        validations = json.loads((state / "rule_validations.json").read_text())
    except Exception:
        validations = {}
    # attach the vote receipt (by rule_id) to each pending rule if we have it
    out = []
    for p in pending:
        rec = validations.get(p.get("rule_id"))
        out.append({
            "rule_id": p.get("rule_id"),
            "technique_id": p.get("technique_id"),
            "technique_name": p.get("technique_name"),
            "confidence": p.get("confidence"),
            "queued_at": p.get("queued_at"),
            "votes": (rec or {}).get("attempts", []),
            "avg_score": (rec or {}).get("avg_score"),
            "backtest_hits": (rec or {}).get("backtest_hits"),
            "healed": len((rec or {}).get("attempts", [])) > 1,
        })
    return JSONResponse({"pending": out})


TECHNIQUE_PLAIN = {
    "t1003.002": "Someone is trying to steal saved Windows passwords from the part of the system that stores them. This is how attackers grab credentials to move deeper.",
    "t1012": "Someone is reading the Windows registry to learn how the machine is set up. Attackers do this to plan their next move.",
    "t1016": "Someone is checking the machine's network settings, its address, gateway, and connections. Attackers map the network before spreading.",
    "t1016.001": "Someone is testing whether the machine can reach the internet. Attackers check this before trying to phone home or download tools.",
    "t1018": "Someone is hunting for other computers on the network. This is how an attacker finds more machines to attack after breaking into one.",
    "t1021.001": "Someone is connecting to this machine using Remote Desktop. Attackers use it to control a computer as if sitting in front of it.",
    "t1021.002": "Someone is connecting to this machine through hidden Windows file shares. Attackers use these to move between computers quietly.",
    "t1033": "Someone is asking who is logged in or who owns this machine. Attackers do this to find valuable accounts to target.",
    "t1035": "Someone is using the Windows service controller to run a program. Attackers abuse this to run code with high privileges.",
    "t1036.005": "A program is pretending to be a trusted, normal Windows file by using a familiar name or location. Attackers do this to hide in plain sight.",
    "t1046": "Someone is scanning the network to find open doors, services and ports they can attack. This is classic early-stage probing before a break-in.",
    "t1048.003": "Someone may be sneaking data out of the network over an unencrypted channel. This is how stolen information leaves the building.",
    "t1049": "Someone is listing the machine's active network connections. Attackers do this to understand what the machine talks to.",
    "t1053.002": "Someone is setting up a hidden scheduled job using the old 'at' command. Attackers use scheduled tasks to keep access or run code later.",
    "t1053.005": "Someone is creating a Windows Scheduled Task. Attackers use these to survive reboots and quietly run code on a timer.",
    "t1055": "A program is injecting its code into another running program. Attackers do this to hide inside a trusted process.",
    "t1057": "Someone is listing the programs currently running. Attackers check this to find security tools or interesting targets.",
    "t1059.001": "Someone is running PowerShell commands. Attackers heavily use PowerShell to run attacks without dropping obvious files.",
    "t1059.003": "Someone is running commands through the Windows command prompt. Attackers use it to chain together quick attack steps.",
    "t1069.002": "Someone is listing the groups in the Windows domain. Attackers do this to find admin groups worth targeting.",
    "t1082": "Someone is collecting basic facts about the machine, its name, version and hardware. Attackers fingerprint a system before deciding how to attack it.",
    "t1083": "Someone is browsing the files and folders on the machine. Attackers do this to find documents and data worth stealing.",
    "t1087.001": "Someone is listing the user accounts on the machine. Attackers do this to find accounts to take over.",
    "t1105": "Someone is downloading a file or tool onto the machine from elsewhere. Attackers do this to bring in their attack tools.",
    "t1110.001": "Someone is guessing passwords by trying many in a row. This is a brute-force attempt to break into an account.",
    "t1112": "Someone is changing the Windows registry. Attackers edit it to disable defenses or keep a foothold.",
    "t1204.002": "Someone opened a file that may be malicious, like a booby-trapped document. This is how many attacks start, a user clicking the wrong thing.",
    "t1216": "Someone is abusing a trusted, signed Windows script to run their own code. Attackers use this to slip past defenses that trust signed files.",
    "t1218.007": "Someone is abusing the trusted Windows installer tool to run code. Attackers use trusted tools so their activity blends in.",
    "t1218.011": "Someone is abusing rundll32, a trusted Windows tool, to run code. This is a very common way attackers hide what they are really doing.",
    "t1482": "Someone is mapping the trust relationships between Windows domains. Attackers use this to plan how to spread across an organization.",
    "t1546.011": "Someone is setting a sneaky trigger that runs their code when certain programs start. Attackers use this to keep access quietly.",
    "t1547.001": "Someone is adding a program to the Windows startup list. Attackers do this so their code runs every time the machine boots.",
    "t1555.004": "Someone is trying to pull saved passwords out of the Windows Credential Manager. Attackers harvest these to log in as someone else.",
    "t1560.001": "Someone is bundling and compressing files, often a sign data is being packaged up to steal.",
    "t1564.001": "Someone is hiding files or folders. Attackers do this to keep their tools out of sight.",
    "t1574.010": "Someone is exploiting weak permissions on a Windows service to run their own code. Attackers use this to gain higher privileges.",
    "t1614.001": "Someone is checking the machine's language and region settings. Some attackers use this to avoid hitting machines in certain countries.",
}

def _technique_plain(tags):
    for t in (tags or []):
        tid = str(t).lower().replace("attack.", "").strip()
        if tid in TECHNIQUE_PLAIN:
            return TECHNIQUE_PLAIN[tid]
    # honest fallback: name the technique without faking specifics
    return None


@app.get("/api/pending-detail/{rule_id}")
def api_pending_detail(rule_id: str):
    """Return a readable view of a pending rule: title, description, and the raw yaml,
    so the reviewer can see exactly what it would catch before approving."""
    import yaml as _yaml
    pdir = HERE / "detections" / "pending"
    fp = pdir / f"{rule_id}.yml"
    if not fp.exists():
        raise HTTPException(status_code=404, detail="rule not found")
    raw = fp.read_text()
    out = {"rule_id": rule_id, "yaml": raw, "title": None, "summary": None,
           "triggers": [], "false_alarms": [], "level": None}
    try:
        doc = _yaml.safe_load(raw)
        out["title"] = doc.get("title")
        out["summary"] = doc.get("description")
        out["level"] = doc.get("level")
        out["meaning"] = _technique_plain(doc.get("tags", []))
        out["false_alarms"] = doc.get("falsepositives", []) or []
        # Translate the detection logic into plain human triggers.
        FIELD_PLAIN = {
            "event.code": lambda v: _event_code_plain(v),
            "process.name": lambda v: "the program is " + _join_or(v),
            "process.executable": lambda v: "the program path matches " + _join_or(v),
            "process.parent.name": lambda v: "it was launched by " + _join_or(v),
            "process.parent.executable": lambda v: "the parent program matches " + _join_or(v),
            "process.command_line": lambda v: "the command line contains " + _join_or(v),
            "source.ip": lambda v: "the connection comes from " + _join_or(v),
            "destination.ip": lambda v: "it connects to " + _join_or(v),
            "destination.port": lambda v: "it targets port " + _join_or(v),
            "file.path": lambda v: "the file path matches " + _join_or(v),
            "user.name": lambda v: "the user is " + _join_or(v),
        }
        det = doc.get("detection", {}) or {}
        for key, block in det.items():
            if key == "condition":
                continue
            negate = ("filter" in key.lower() or "exclude" in key.lower())
            if isinstance(block, dict):
                for fld, val in block.items():
                    base = fld.split("|")[0]
                    fn = FIELD_PLAIN.get(base)
                    phrase = fn(val) if fn else (base + " matches " + _join_or(val))
                    if negate:
                        phrase = "NOT when " + phrase
                    out["triggers"].append(phrase)
    except Exception:
        pass
    return JSONResponse(out)


def _join_or(v):
    if not isinstance(v, list):
        v = [v]
    v = [str(x).strip("*") for x in v]
    if len(v) == 1:
        return v[0]
    if len(v) <= 4:
        return ", ".join(v[:-1]) + " or " + v[-1]
    return ", ".join(v[:3]) + f" or {len(v)-3} more"


def _event_code_plain(v):
    codes = {"1": "a program starts", "3": "a network connection is made",
             "11": "a file is created", "13": "the registry is changed",
             "7": "a code library loads", "22": "a DNS query is made",
             "8": "a process injects into another"}
    key = str(v[0] if isinstance(v, list) else v)
    return codes.get(key, f"a Sysmon event of type {key} occurs")


@app.post("/api/approve/{rule_id}")
def api_approve(rule_id: str, request: Request):
    _localhost_only(request)
    import subprocess
    r = subprocess.run(["python3", str(HERE / "approve.py"), "approve", rule_id],
                       capture_output=True, text=True, cwd=str(HERE))
    ok = r.returncode == 0
    return JSONResponse({"ok": ok, "output": (r.stdout or "") + (r.stderr or "")})


@app.post("/api/reject/{rule_id}")
def api_reject(rule_id: str, request: Request):
    _localhost_only(request)
    import subprocess
    r = subprocess.run(["python3", str(HERE / "approve.py"), "reject", rule_id],
                       capture_output=True, text=True, cwd=str(HERE))
    ok = r.returncode == 0
    return JSONResponse({"ok": ok, "output": (r.stdout or "") + (r.stderr or "")})


@app.get("/review")
def review_page():
    return FileResponse(WEB_DIR / "review.html")


@app.get("/water")
def water_page():
    return FileResponse(WEB_DIR / "water.html")


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
