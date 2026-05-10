#!/usr/bin/env python3
"""
1xLoZec Detection Lab
h4voc_water — Autonomous Detection Engineering Pipeline

Loads credentials from .env automatically.
Set STOP_H4VOC_WATER=true in .env to pause all auto-deployment.
"""

import os
import sys
import json
import uuid
import ssl
import smtplib
import subprocess
import warnings
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from pathlib import Path

import requests
import anthropic
from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ── Configuration ──────────────────────────────────────────────────────────────
ELASTIC_URL        = os.getenv("ELASTIC_URL", "https://10.0.0.1:9200")
ELASTIC_API_KEY    = os.getenv("ELASTIC_API_KEY", "")
ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
GMAIL_FROM         = os.getenv("GMAIL_FROM", "")
GMAIL_TO           = os.getenv("GMAIL_TO", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
TARGET_HOST        = os.getenv("TARGET_HOST", "*")
SIGMA_OUTPUT_DIR   = "detections/sigma"
STATE_DIR          = Path("state")

STOP_H4VOC_WATER = os.getenv("STOP_H4VOC_WATER", "false").lower() == "true"

ALL_TACTICS = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
    "reconnaissance", "resource-development"
]

SYSMON_EVENT_IDS = ["1","3","7","8","10","11","12","13","14","15","17","18","22","23","25"]

SYSMON_ECS_FIELDS = [
    "@timestamp","event.code","event.category","event.type","event.action",
    "winlog.channel","host.name",
    "process.executable","process.name","process.command_line","process.args",
    "process.pid","process.entity_id","process.hash.sha256","process.hash.sha1",
    "process.hash.md5","process.pe.original_file_name","process.pe.description",
    "process.pe.company","process.parent.executable","process.parent.name",
    "process.parent.command_line","process.parent.pid","process.parent.entity_id",
    "user.name","user.domain","winlog.event_data.IntegrityLevel",
    "winlog.event_data.CurrentDirectory",
    "destination.ip","destination.port","destination.domain",
    "source.ip","source.port","network.transport","network.protocol",
    "winlog.event_data.ImageLoaded","winlog.event_data.Signed",
    "winlog.event_data.Signature","winlog.event_data.SignatureStatus",
    "file.hash.sha256","file.path","file.name","file.extension","file.directory",
    "winlog.event_data.SourceImage","winlog.event_data.TargetImage",
    "winlog.event_data.StartModule","winlog.event_data.StartFunction",
    "winlog.event_data.GrantedAccess","winlog.event_data.CallTrace",
    "registry.key","registry.value","registry.path","registry.data.strings",
    "dns.question.name","dns.question.type",
    "winlog.event_data.PipeName","winlog.event_data.TargetFilename",
    "related.hash","related.ip","related.user",
]


# ── State ──────────────────────────────────────────────────────────────────────
def load_state():
    STATE_DIR.mkdir(exist_ok=True)
    def load(f): return json.loads(f.read_text()) if f.exists() else None
    seen   = load(STATE_DIR / "seen_techniques.json") or {}
    last   = load(STATE_DIR / "last_run.json") or {}
    log    = load(STATE_DIR / "hunt_log.json") or []
    digest = load(STATE_DIR / "weekly_digest.json") or {"week_start": None}
    return seen, last, log, digest

def save_state(seen, last, log, digest):
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "seen_techniques.json").write_text(json.dumps(seen, indent=2))
    (STATE_DIR / "last_run.json").write_text(json.dumps(last, indent=2))
    (STATE_DIR / "hunt_log.json").write_text(json.dumps(log, indent=2))
    (STATE_DIR / "weekly_digest.json").write_text(json.dumps(digest, indent=2))

def git_push_state():
    try:
        subprocess.run(["git", "add", "state/"], check=True, capture_output=True)
        result = subprocess.run(["git", "commit", "-m", "update: h4voc_water state"],
                                capture_output=True, text=True)
        if "nothing to commit" not in result.stdout:
            subprocess.run(["git", "pull", "--rebase"], check=True, capture_output=True)
            subprocess.run(["git", "push"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pass

def coverage_stats(seen):
    covered_tactics = {v.get("tactic","") for v in seen.values() if v.get("tactic")}
    covered = len(covered_tactics)
    total   = len(ALL_TACTICS)
    pct     = int((covered / total) * 100) if total else 0
    uncovered = [t for t in ALL_TACTICS if t not in covered_tactics]
    return covered, total, pct, uncovered

def should_send_weekly_digest(digest):
    now = datetime.now(timezone.utc)
    if now.weekday() != 6:
        return False
    ws = digest.get("week_start")
    return (not ws) or (now - datetime.fromisoformat(ws)).days >= 6


# ── Helpers ────────────────────────────────────────────────────────────────────
def flatten_dict(d, parent_key="", sep="."):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


# ── Elasticsearch ──────────────────────────────────────────────────────────────
def query_elasticsearch(lookback_minutes):
    headers = {"Content-Type": "application/json"}
    if ELASTIC_API_KEY:
        headers["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"

    host_filter = {"match_all": {}} if TARGET_HOST == "*" else {"term": {"host.name": TARGET_HOST}}

    query = {
        "size": 100,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": SYSMON_ECS_FIELDS,
        "query": {"bool": {
            "must": [host_filter,
                     {"range": {"@timestamp": {"gte": f"now-{lookback_minutes}m", "lte": "now"}}}],
            "filter": [{"bool": {"should": [
                {"term": {"winlog.channel": "Microsoft-Windows-Sysmon/Operational"}},
                {"terms": {"event.code": SYSMON_EVENT_IDS}},
            ]}}]
        }}
    }

    r = requests.post(f"{ELASTIC_URL}/logs-*/_search",
                      headers=headers, json=query, verify=False, timeout=30)
    if r.status_code != 200:
        print(f"Elasticsearch error: {r.status_code}")
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


# ── Preprocessing ──────────────────────────────────────────────────────────────
def preprocess_events(events):
    events = [flatten_dict(e) for e in events]
    iocs = {k: set() for k in [
        "processes","parent_processes","command_lines","process_hashes_sha256",
        "original_filenames","integrity_levels","users","destination_ips",
        "destination_ports","destination_domains","protocols","file_paths",
        "file_extensions","loaded_images","unsigned_images","registry_keys",
        "registry_values","dns_queries","remote_thread_targets",
        "process_access_targets","granted_access_masks","pipe_names",
        "event_codes","hosts",
    ]}
    for e in events:
        code = str(e.get("event.code",""))
        if code: iocs["event_codes"].add(code)
        if e.get("host.name"): iocs["hosts"].add(e["host.name"])
        if e.get("process.name"): iocs["processes"].add(e["process.name"])
        if e.get("process.parent.name"): iocs["parent_processes"].add(e["process.parent.name"])
        if e.get("process.command_line") and len(str(e["process.command_line"])) < 500:
            iocs["command_lines"].add(str(e["process.command_line"]))
        if e.get("process.hash.sha256"): iocs["process_hashes_sha256"].add(e["process.hash.sha256"])
        if e.get("process.pe.original_file_name"): iocs["original_filenames"].add(e["process.pe.original_file_name"])
        if e.get("winlog.event_data.IntegrityLevel"): iocs["integrity_levels"].add(e["winlog.event_data.IntegrityLevel"])
        if e.get("user.name"): iocs["users"].add(e["user.name"])
        if e.get("destination.ip"): iocs["destination_ips"].add(e["destination.ip"])
        if e.get("destination.port"): iocs["destination_ports"].add(str(e["destination.port"]))
        if e.get("destination.domain"): iocs["destination_domains"].add(e["destination.domain"])
        if e.get("network.transport"): iocs["protocols"].add(e["network.transport"])
        if e.get("winlog.event_data.ImageLoaded"):
            iocs["loaded_images"].add(e["winlog.event_data.ImageLoaded"].split("\\")[-1])
            if e.get("winlog.event_data.Signed") == "false":
                iocs["unsigned_images"].add(e["winlog.event_data.ImageLoaded"])
        if e.get("winlog.event_data.TargetFilename"): iocs["file_paths"].add(e["winlog.event_data.TargetFilename"])
        if e.get("file.path"): iocs["file_paths"].add(e["file.path"])
        if e.get("file.extension"): iocs["file_extensions"].add(e["file.extension"])
        if e.get("registry.key"): iocs["registry_keys"].add(e["registry.key"])
        if e.get("registry.value"): iocs["registry_values"].add(e["registry.value"])
        if e.get("dns.question.name"): iocs["dns_queries"].add(e["dns.question.name"])
        if e.get("winlog.event_data.TargetImage"):
            t = e["winlog.event_data.TargetImage"].split("\\")[-1]
            if code == "8": iocs["remote_thread_targets"].add(t)
            if code == "10": iocs["process_access_targets"].add(t)
        if e.get("winlog.event_data.GrantedAccess"): iocs["granted_access_masks"].add(e["winlog.event_data.GrantedAccess"])
        if e.get("winlog.event_data.PipeName"): iocs["pipe_names"].add(e["winlog.event_data.PipeName"])
    return {k: sorted(list(v)) for k, v in iocs.items() if v}


# ── Stage 1: Claude analyzes ───────────────────────────────────────────────────
def analyze_with_claude(iocs, events_count, seen, lookback):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = f"""You are a detection engineer analyzing Windows endpoint telemetry. Analyze {events_count} events from the last {lookback} minutes.

IOC Summary:
{json.dumps(iocs, indent=2)}

Techniques already covered (skip these):
{json.dumps(list(seen.keys()))}

Return JSON only:
{{
  "technique_id": "T1XXX.XXX",
  "technique_name": "Full Technique Name",
  "tactic": "tactic-name",
  "already_covered": true or false,
  "confidence": "high" or "medium" or "low",
  "plain_english_summary": "One sentence a non-technical executive would understand. What happened and why it matters. No jargon.",
  "reasoning": "Two sentences explaining what you saw and why you identified this technique.",
  "key_indicators": ["the 3 most distinctive things you saw"],
  "detection_focus": "One sentence on what the rule specifically watches for.",
  "next_simulation": "T1XXX — Technique Name — one sentence on why this gap matters for defense.",
  "skip_reason": "Only fill this if already_covered is true, otherwise leave empty."
}}"""
    msg = client.messages.create(model="claude-sonnet-4-6", max_tokens=1024,
                                  messages=[{"role":"user","content":prompt}])
    return json.loads(msg.content[0].text.replace("```json","").replace("```","").strip())


# ── Stage 2: Generate Sigma Rule ───────────────────────────────────────────────
def generate_sigma_rule(iocs, analysis):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    rule_id = str(uuid.uuid4())
    today   = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    prompt  = f"""You are a detection engineer writing a Sigma rule for Elastic SIEM with Sysmon data using ECS field names.

ATT&CK Technique: {analysis['technique_id']} — {analysis['technique_name']}
Tactic: {analysis['tactic']}
Detection focus: {analysis['detection_focus']}
Key indicators: {analysis['key_indicators']}
Reasoning: {analysis['reasoning']}

IOCs from telemetry:
{json.dumps(iocs, indent=2)}

ECS fields to use: process.name, process.executable, process.command_line,
process.parent.name, process.parent.executable, event.code, file.path,
registry.key, dns.question.name, destination.ip, destination.port,
winlog.event_data.ImageLoaded, winlog.event_data.GrantedAccess,
winlog.event_data.IntegrityLevel, winlog.event_data.PipeName

Rules: ECS field names only. Most distinctive indicators only. Realistic false positives. Correct severity.
Required: id: {rule_id}, date: {today}, author: 1xLoZec, status: experimental

Return valid Sigma YAML only. No markdown. No explanation."""
    msg = client.messages.create(model="claude-sonnet-4-6", max_tokens=2048,
                                  messages=[{"role":"user","content":prompt}])
    sigma = msg.content[0].text.strip().replace("```yaml","").replace("```","").strip()
    return sigma, rule_id


# ── Save and Push ──────────────────────────────────────────────────────────────
def save_and_push(sigma_yaml, analysis, rule_id):
    tid   = analysis["technique_id"].replace(".","-")
    tname = (analysis["technique_name"].lower()
             .replace(" ","-").replace("/","-")
             .replace("(","").replace(")",""))
    filename = f"{tid}-{tname}-autogen.yml"
    filepath = os.path.join(SIGMA_OUTPUT_DIR, filename)
    os.makedirs(SIGMA_OUTPUT_DIR, exist_ok=True)
    with open(filepath, "w") as f:
        f.write(sigma_yaml)
    try:
        subprocess.run(["git","add",filepath], check=True, capture_output=True)
        msg = f"auto-generate: {analysis['technique_id']} {analysis['technique_name']} [{rule_id[:8]}]"
        r   = subprocess.run(["git","commit","-m",msg], check=True, capture_output=True, text=True)
        print(f"  {r.stdout.strip()}")
        subprocess.run(["git","pull","--rebase"], check=True, capture_output=True)
        subprocess.run(["git","push"], check=True, capture_output=True)
        print("  Pushed to GitHub. CI/CD pipeline is validating and deploying to Kibana.")
    except subprocess.CalledProcessError as e:
        print(f"  Git failed: {e}")
    return filepath


# ── Email ──────────────────────────────────────────────────────────────────────
def send_email(subject, html):
    if not all([GMAIL_FROM, GMAIL_TO, GMAIL_APP_PASSWORD]):
        print("  Email not configured.")
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"]    = GMAIL_FROM
        msg["To"]      = GMAIL_TO
        msg.set_content("Open in a modern email client to view this report.")
        msg.add_alternative(html, subtype="html")
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as s:
            s.login(GMAIL_FROM, GMAIL_APP_PASSWORD)
            s.send_message(msg)
        print(f"  Email sent to {GMAIL_TO}")
    except Exception as e:
        print(f"  Email failed: {e}")


def _coverage_bar(pct):
    filled = int(pct / 5)
    return (
        f'<span style="color:#2563eb;font-family:monospace;font-size:15px;">{"█"*filled}</span>'
        f'<span style="color:#e2e8f0;font-family:monospace;font-size:15px;">{"░"*(20-filled)}</span>'
    )


def email_rule_deployed(analysis, iocs, sigma_yaml, rule_id, events_count, lookback, filepath, seen):
    now  = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    conf = analysis.get("confidence","unknown").capitalize()
    conf_color = {"High":"#16a34a","Medium":"#d97706","Low":"#dc2626"}.get(conf,"#64748b")

    covered, total, pct, _ = coverage_stats(seen)
    bar = _coverage_bar(pct)

    indicators_html = "".join(
        f'<tr><td style="padding:8px 16px;font-family:monospace;font-size:12px;'
        f'color:#1e293b;border-bottom:1px solid #f1f5f9;">{ind}</td></tr>'
        for ind in analysis.get("key_indicators",[])
    )

    conf_badge = (
        f'<span style="display:inline-block;background:{conf_color}15;color:{conf_color};'
        f'border:1px solid {conf_color}40;border-radius:4px;padding:2px 10px;'
        f'font-size:12px;font-weight:600;letter-spacing:0.5px;">{conf}</span>'
    )

    medium_note = ""
    if conf == "Medium":
        medium_note = (
            '<tr><td style="padding:0 40px 24px;">'
            '<p style="margin:0;padding:12px 16px;background:#fffbeb;border:1px solid #fbbf24;'
            'border-radius:6px;font-size:13px;color:#92400e;">'
            'This rule was deployed at medium confidence. Review it in Kibana before relying on it in production.'
            '</p></td></tr>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Detection Rule Deployed</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;">
<tr><td align="center" style="padding:32px 16px;">
<table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e2e8f0;">

<tr><td style="padding:0;">
  <div style="background:#2563eb;border-radius:8px 8px 0 0;height:4px;"></div>
</td></tr>

<tr><td style="padding:32px 40px 24px;">
  <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:1.5px;color:#94a3b8;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:0 0 4px;font-size:22px;font-weight:700;color:#0f172a;line-height:1.3;">Detection Rule Deployed</h1>
  <p style="margin:0;font-size:13px;color:#94a3b8;">{now}</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0;font-size:15px;color:#334155;line-height:1.6;padding:16px 20px;background:#f8fafc;border-left:3px solid #2563eb;border-radius:0 6px 6px 0;">{analysis.get("plain_english_summary","")}</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">
  <tr>
    <td style="padding:16px 20px;border-right:1px solid #e2e8f0;text-align:center;width:33%;">
      <p style="margin:0 0 2px;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Technique</p>
      <p style="margin:0;font-size:16px;font-weight:700;color:#2563eb;font-family:monospace;">{analysis["technique_id"]}</p>
    </td>
    <td style="padding:16px 20px;border-right:1px solid #e2e8f0;text-align:center;width:33%;">
      <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Confidence</p>
      <p style="margin:0;">{conf_badge}</p>
    </td>
    <td style="padding:16px 20px;text-align:center;width:34%;">
      <p style="margin:0 0 2px;font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;">Tactic</p>
      <p style="margin:0;font-size:13px;font-weight:600;color:#0f172a;">{analysis["tactic"].title()}</p>
    </td>
  </tr>
  </table>
</td></tr>

{medium_note}

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">ATT&amp;CK Coverage</p>
  <p style="margin:0 0 6px;font-size:14px;line-height:1;">{bar} &nbsp;{pct}%</p>
  <p style="margin:0;font-size:12px;color:#94a3b8;">{covered} of {total} attack categories have at least one detection rule</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Why This Was Flagged</p>
  <p style="margin:0;font-size:14px;color:#334155;line-height:1.7;">{analysis.get("reasoning","")}</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">The 3 Strongest Signals</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;background:#f8fafc;">
  {indicators_html}
  </table>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">What the Rule Watches For</p>
  <p style="margin:0;font-size:14px;color:#334155;line-height:1.7;">{analysis.get("detection_focus","")}</p>
</td></tr>

<tr><td style="padding:0 40px 32px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Recommended Next Step</p>
  <p style="margin:0;font-size:14px;color:#334155;line-height:1.7;padding:14px 16px;background:#f0f9ff;border-radius:6px;border:1px solid #bae6fd;">{analysis.get("next_simulation","")}</p>
</td></tr>

<tr><td style="padding:0 40px 32px;">
  <table cellpadding="0" cellspacing="0">
  <tr>
    <td style="padding-right:12px;">
      <a href="https://github.com/1xLoZec/detection-lab/actions"
         style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;
                padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;">
        CI/CD Pipeline
      </a>
    </td>
    <td>
      <a href="https://1xlozec.com/app/security/rules"
         style="display:inline-block;background:#ffffff;color:#2563eb;text-decoration:none;
                padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;
                border:1px solid #2563eb;">
        Kibana Rules
      </a>
    </td>
  </tr>
  </table>
</td></tr>

<tr><td style="padding:16px 40px;border-top:1px solid #f1f5f9;">
  <p style="margin:0;font-size:11px;color:#cbd5e1;font-family:monospace;">{rule_id}</p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    send_email(
        f"[h4voc_water] {analysis['technique_id']} — {analysis['technique_name']} ({conf} confidence)",
        html
    )


def email_nothing_new(events_count, lookback, analysis, seen):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    covered, total, pct, _ = coverage_stats(seen)
    bar = _coverage_bar(pct)
    reason = analysis.get("skip_reason") or "This technique already has a detection rule."
    next_sim = analysis.get("next_simulation","")

    covered_rows = "".join(
        f'<tr><td style="padding:6px 16px;font-size:13px;color:#64748b;font-family:monospace;'
        f'border-bottom:1px solid #f1f5f9;">{t} — {seen[t].get("technique_name","")}</td></tr>'
        for t in seen
    ) or '<tr><td style="padding:12px 16px;font-size:13px;color:#94a3b8;">None yet.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;">
<tr><td align="center" style="padding:32px 16px;">
<table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e2e8f0;">

<tr><td><div style="background:#64748b;border-radius:8px 8px 0 0;height:4px;"></div></td></tr>

<tr><td style="padding:32px 40px 24px;">
  <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:1.5px;color:#94a3b8;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:0 0 4px;font-size:22px;font-weight:700;color:#0f172a;">Hunt Complete</h1>
  <p style="margin:0;font-size:13px;color:#94a3b8;">{now}</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0;font-size:14px;color:#334155;line-height:1.7;">Reviewed {events_count} events from the last {lookback} minutes. {reason} No new rule was generated.</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">ATT&amp;CK Coverage</p>
  <p style="margin:0 0 6px;font-size:14px;">{bar} &nbsp;{pct}%</p>
  <p style="margin:0;font-size:12px;color:#94a3b8;">{covered} of {total} attack categories covered &nbsp;·&nbsp; {len(seen)} techniques in library</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Recommended Next Step</p>
  <p style="margin:0;font-size:14px;color:#334155;padding:14px 16px;background:#f0f9ff;border-radius:6px;border:1px solid #bae6fd;">{next_sim}</p>
</td></tr>

<tr><td style="padding:0 40px 32px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Techniques Already Covered</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">
  {covered_rows}
  </table>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""
    send_email("[h4voc_water] Hunt complete — no new techniques found", html)


def email_weekly_digest(seen, log):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y")
    covered, total, pct, uncovered = coverage_stats(seen)
    bar = _coverage_bar(pct)

    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    week_log  = [e for e in log if datetime.fromisoformat(e["timestamp"]) > week_ago]
    deployed  = [e for e in week_log if e.get("result") == "deployed"]

    deployed_rows = "".join(
        f'<tr>'
        f'<td style="padding:8px 16px;font-size:13px;font-family:monospace;color:#2563eb;border-bottom:1px solid #f1f5f9;">{e["technique_id"]}</td>'
        f'<td style="padding:8px 16px;font-size:13px;color:#334155;border-bottom:1px solid #f1f5f9;">{e["technique_name"]}</td>'
        f'<td style="padding:8px 16px;font-size:12px;color:#94a3b8;border-bottom:1px solid #f1f5f9;text-align:right;">{e["confidence"].capitalize()}</td>'
        f'</tr>'
        for e in deployed
    ) or '<tr><td colspan="3" style="padding:12px 16px;font-size:13px;color:#94a3b8;">No rules deployed this week.</td></tr>'

    uncovered_html = "".join(
        f'<span style="display:inline-block;margin:3px;padding:4px 10px;background:#f1f5f9;'
        f'border-radius:4px;font-size:12px;color:#64748b;">{t.replace("-"," ").title()}</span>'
        for t in uncovered
    ) or '<span style="font-size:13px;color:#16a34a;">All major tactics covered.</span>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;">
<tr><td align="center" style="padding:32px 16px;">
<table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e2e8f0;">

<tr><td><div style="background:#2563eb;border-radius:8px 8px 0 0;height:4px;"></div></td></tr>

<tr><td style="padding:32px 40px 24px;">
  <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:1.5px;color:#94a3b8;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:0 0 4px;font-size:22px;font-weight:700;color:#0f172a;">Weekly Detection Report</h1>
  <p style="margin:0;font-size:13px;color:#94a3b8;">Week ending {now}</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">
  <tr>
    <td style="padding:20px;text-align:center;border-right:1px solid #e2e8f0;">
      <p style="margin:0;font-size:32px;font-weight:700;color:#2563eb;">{len(deployed)}</p>
      <p style="margin:4px 0 0;font-size:12px;color:#94a3b8;">Rules Deployed</p>
    </td>
    <td style="padding:20px;text-align:center;border-right:1px solid #e2e8f0;">
      <p style="margin:0;font-size:32px;font-weight:700;color:#0f172a;">{len(week_log)}</p>
      <p style="margin:4px 0 0;font-size:12px;color:#94a3b8;">Hunts Run</p>
    </td>
    <td style="padding:20px;text-align:center;">
      <p style="margin:0;font-size:32px;font-weight:700;color:#16a34a;">{pct}%</p>
      <p style="margin:4px 0 0;font-size:12px;color:#94a3b8;">Tactic Coverage</p>
    </td>
  </tr>
  </table>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Overall Coverage</p>
  <p style="margin:0 0 6px;font-size:14px;">{bar} &nbsp;{pct}%</p>
  <p style="margin:0;font-size:12px;color:#94a3b8;">{covered} of {total} attack categories &nbsp;·&nbsp; {len(seen)} techniques in library</p>
</td></tr>

<tr><td style="padding:0 40px 24px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Rules Deployed This Week</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0;border-radius:6px;overflow:hidden;">
  {deployed_rows}
  </table>
</td></tr>

<tr><td style="padding:0 40px 32px;">
  <p style="margin:0 0 10px;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;">Attack Categories Without Coverage</p>
  <div>{uncovered_html}</div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""
    send_email(f"[h4voc_water] Weekly Report — {pct}% coverage — {now}", html)


def email_stopped():
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px;">
<table width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e2e8f0;">
<tr><td><div style="background:#dc2626;border-radius:8px 8px 0 0;height:4px;"></div></td></tr>
<tr><td style="padding:32px 40px;">
  <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:1.5px;color:#94a3b8;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:0 0 16px;font-size:22px;font-weight:700;color:#0f172a;">Pipeline Paused</h1>
  <p style="margin:0;font-size:14px;color:#334155;line-height:1.7;">h4voc_water ran but STOP_H4VOC_WATER is set to true in your .env file. No data was queried and no rules were generated. Set it to false to resume.</p>
  <p style="margin:12px 0 0;font-size:12px;color:#94a3b8;">{now}</p>
</td></tr>
</table>
</td></tr></table>
</body>
</html>"""
    send_email("[h4voc_water] Pipeline is paused", html)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("="*60)
    print("h4voc_water — 1xLoZec Detection Lab")
    print("="*60)

    if not ANTHROPIC_API_KEY:
        print("Error: ANTHROPIC_API_KEY not set. Check your .env file.")
        sys.exit(1)

    if STOP_H4VOC_WATER:
        print("Pipeline paused. STOP_H4VOC_WATER=true in .env")
        email_stopped()
        sys.exit(0)

    seen, last, log, digest = load_state()
    now_ts = datetime.now(timezone.utc).isoformat()

    if should_send_weekly_digest(digest):
        print("Sending weekly digest...")
        email_weekly_digest(seen, log)
        digest["week_start"] = now_ts

    last_run_ts = last.get("timestamp")
    if last_run_ts:
        mins_since = int((datetime.now(timezone.utc) - datetime.fromisoformat(last_run_ts)).total_seconds() / 60)
        lookback   = max(10, min(mins_since + 5, 1440))
        print(f"Last run {mins_since} minutes ago. Looking back {lookback} minutes.")
    else:
        lookback = 60
        print(f"First run. Looking back {lookback} minutes.")

    print(f"\n[1/4] Querying Elasticsearch...")
    events = query_elasticsearch(lookback)
    print(f"  Found {len(events)} events.")

    if not events:
        print("  No events found. Run an Atomic Red Team simulation first.")
        log.append({"timestamp":now_ts,"result":"no_events","lookback":lookback})
        last["timestamp"] = now_ts
        save_state(seen, last, log, digest)
        git_push_state()
        sys.exit(0)

    print(f"\n[2/4] Preprocessing...")
    iocs = preprocess_events(events)

    print(f"\n[3/4] Claude is analyzing...")
    analysis = analyze_with_claude(iocs, len(events), seen, lookback)
    print(f"  Technique:  {analysis['technique_id']} — {analysis['technique_name']}")
    print(f"  Confidence: {analysis['confidence']}")
    print(f"  Covered:    {analysis['already_covered']}")
    print(f"  Summary:    {analysis.get('plain_english_summary','')}")

    last["timestamp"] = now_ts

    if analysis["already_covered"] or analysis["confidence"] == "low":
        reason = "already covered" if analysis["already_covered"] else "confidence too low"
        print(f"\n  Skipping ({reason}). Next: {analysis.get('next_simulation','')}")
        log.append({"timestamp":now_ts,"result":reason.replace(" ","_"),
                    "technique_id":analysis["technique_id"],
                    "technique_name":analysis["technique_name"],
                    "confidence":analysis["confidence"],"lookback":lookback})
        save_state(seen, last, log, digest)
        git_push_state()
        email_nothing_new(len(events), lookback, analysis, seen)
        covered, total, pct, _ = coverage_stats(seen)
        print(f"\n{'='*60}")
        print(f"h4voc_water complete. Nothing new to deploy.")
        print(f"Coverage: {pct}% — {len(seen)} techniques in library.")
        print("="*60)
        return

    print(f"\n[4/4] Generating and deploying Sigma rule...")
    sigma_yaml, rule_id = generate_sigma_rule(iocs, analysis)

    if not all(f in sigma_yaml for f in ["title:","id:","logsource:","detection:","condition:"]):
        print("  Rule failed validation.")
        sys.exit(1)

    filepath = save_and_push(sigma_yaml, analysis, rule_id)

    seen[analysis["technique_id"]] = {
        "technique_name": analysis["technique_name"],
        "tactic":         analysis["tactic"],
        "rule_id":        rule_id,
        "deployed_at":    now_ts,
        "confidence":     analysis["confidence"],
    }
    log.append({"timestamp":now_ts,"result":"deployed",
                "technique_id":analysis["technique_id"],
                "technique_name":analysis["technique_name"],
                "confidence":analysis["confidence"],
                "rule_id":rule_id,"filepath":filepath,"lookback":lookback})

    save_state(seen, last, log, digest)
    git_push_state()
    email_rule_deployed(analysis, iocs, sigma_yaml, rule_id, len(events), lookback, filepath, seen)

    covered, total, pct, _ = coverage_stats(seen)
    print(f"\n{'='*60}")
    print(f"h4voc_water complete.")
    print(f"Technique:  {analysis['technique_id']} — {analysis['technique_name']}")
    print(f"Confidence: {analysis['confidence']}")
    print(f"Coverage:   {pct}% — {len(seen)} techniques in library.")
    print(f"Next:       {analysis.get('next_simulation','')}")
    print("="*60)


if __name__ == "__main__":
    main()
