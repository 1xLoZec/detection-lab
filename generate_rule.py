#!/usr/bin/env python3
"""
1xLoZec Detection Lab
h4voc_water — Autonomous Detection Engineering Pipeline

Named after Havoc the dog and his water bowl.
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
    def _l(f): return json.loads(f.read_text()) if f.exists() else None
    return (
        _l(STATE_DIR / "seen_techniques.json") or {},
        _l(STATE_DIR / "last_run.json") or {},
        _l(STATE_DIR / "hunt_log.json") or [],
        _l(STATE_DIR / "weekly_digest.json") or {"week_start": None},
    )

def save_state(seen, last, log, digest):
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "seen_techniques.json").write_text(json.dumps(seen, indent=2))
    (STATE_DIR / "last_run.json").write_text(json.dumps(last, indent=2))
    (STATE_DIR / "hunt_log.json").write_text(json.dumps(log, indent=2))
    (STATE_DIR / "weekly_digest.json").write_text(json.dumps(digest, indent=2))

def git_push_state():
    try:
        subprocess.run(["git","add","state/"], check=True, capture_output=True)
        r = subprocess.run(["git","commit","-m","update: h4voc_water state"],
                           capture_output=True, text=True)
        if "nothing to commit" not in r.stdout:
            subprocess.run(["git","pull","--rebase"], check=True, capture_output=True)
            subprocess.run(["git","push"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pass

def coverage_stats(seen):
    covered_tactics = {v.get("tactic","") for v in seen.values() if v.get("tactic")}
    covered  = len(covered_tactics)
    total    = len(ALL_TACTICS)
    pct      = int((covered / total) * 100) if total else 0
    uncovered = [t for t in ALL_TACTICS if t not in covered_tactics]
    return covered, total, pct, uncovered

def _fmt_next(raw):
    """Split next_simulation string so technique ID+name is line 1, description is line 2."""
    # Format: "T1049 — Technique Name — description..."
    parts = raw.split(" — ", 2)
    if len(parts) == 3:
        return f"{parts[0]} — {parts[1]}<br>{parts[2]}"
    return raw

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
  "plain_english_summary": "One sentence a non-technical executive understands. What happened and why it matters. No jargon.",
  "reasoning": "Two sentences explaining what you saw and why you identified this technique.",
  "key_indicators": ["the 3 most distinctive things you saw"],
  "detection_focus": "One sentence on what the rule specifically watches for.",
  "next_simulation": "T1XXX — Technique Name — one sentence on why this gap matters for defense.",
  "severity": "high, medium, or low based on how dangerous this ATT\&CK technique is objectively",
  "false_positive_risk": "low, medium, or high — how likely this rule is to fire on legitimate activity",
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
        commit_msg = f"auto-generate: {analysis['technique_id']} {analysis['technique_name']} [{rule_id[:8]}]"
        r = subprocess.run(["git","commit","-m",commit_msg], check=True, capture_output=True, text=True)
        print(f"  {r.stdout.strip()}")
        subprocess.run(["git","pull","--rebase"], check=True, capture_output=True)
        subprocess.run(["git","push"], check=True, capture_output=True)
        print("  Pushed to GitHub. CI/CD pipeline is validating and deploying to Kibana.")
    except subprocess.CalledProcessError as e:
        print(f"  Git failed: {e}")
    return filepath


# ── Email shared helpers ───────────────────────────────────────────────────────
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

# shared color palette
BG      = "#0d1117"
CARD    = "#161b22"
BORDER  = "#30363d"
GREEN   = "#3fb950"
GREEN_D = "#1c3a24"
YELLOW  = "#d29922"
RED     = "#da3633"
TEXT    = "#e6edf3"
MUTED   = "#8b949e"
FAINT   = "#6e7681"

# ASCII water drop — terminal boot style, renders via monospace pre in all major clients
ASCII_DROP = (
    '<div style="font-family:\'SF Mono\',\'Fira Code\',\'Consolas\',monospace;'
    f'white-space:pre;font-size:9px;line-height:1.4;color:{FAINT};display:inline-block;">'
    "   .  \n"
    "  ( ) \n"
    " (   )\n"
    "  ) ( \n"
    "   =  "
    '</div>'
)

def fmt_next(raw):
    parts = raw.split(" — ", 2)
    if len(parts) == 3:
        return f"{parts[0]} — {parts[1]}<br>{parts[2]}"
    return raw

def _bar(pct):
    filled = int(pct / 5)
    return (
        f'<span style="font-family:monospace;font-size:14px;color:{GREEN};">{"█"*filled}</span>'
        f'<span style="font-family:monospace;font-size:14px;color:#4a5568;">{"░"*(20-filled)}</span>'
    )

def _section_label(text):
    return (
        f'<p style="margin:0 0 10px;font-size:10px;font-weight:600;letter-spacing:2px;'
        f'color:{MUTED};text-transform:uppercase;">{text}</p>'
    )

def _wrapper(content, footer=""):
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>h4voc_water</title></head>
<body style="margin:0;padding:0;background:{BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};">
<tr><td align="center" style="padding:32px 16px;">
<table width="580" cellpadding="0" cellspacing="0"
       style="background:{CARD};border-radius:10px;border:1px solid {BORDER};overflow:hidden;">

<tr><td style="padding:22px 36px 16px;border-bottom:1px solid {BORDER};">
  <p style="margin:0;font-size:10px;font-weight:600;letter-spacing:2px;color:{MUTED};text-transform:uppercase;">1xLoZec Detection Lab</p>
</td></tr>

{content}

{'<tr><td style="padding:14px 36px;border-top:1px solid ' + BORDER + ';">' + footer + '</td></tr>' if footer else ''}

</table>
</td></tr>
</table>
</body>
</html>"""


# ── Email: rule deployed ───────────────────────────────────────────────────────
def email_rule_deployed(analysis, iocs, sigma_yaml, rule_id, events_count, lookback, filepath, seen):
    now  = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    conf = analysis.get("confidence","unknown").capitalize()
    conf_color = {"High": RED, "Medium": YELLOW, "Low": GREEN}.get(conf, MUTED)

    covered, total, pct, _ = coverage_stats(seen)
    bar = _bar(pct)

    indicators_html = "".join(
        f'<tr><td style="padding:8px 14px;font-family:\'SF Mono\',\'Fira Code\',monospace;'
        f'font-size:12px;color:{GREEN};border-bottom:1px solid {BORDER};">{ind}</td></tr>'
        for ind in analysis.get("key_indicators",[])
    )

    # Confidence — always blue, distinct from severity
    conf_badge = (
        '<span style="display:inline-block;background:#388bfd22;color:#388bfd;'
        'border:1px solid #388bfd55;border-radius:4px;padding:2px 8px;'
        f'font-size:11px;font-weight:700;letter-spacing:1px;font-family:monospace;">{conf.upper()}</span>'
    )

    # Severity — traffic light, how dangerous the technique is
    sev       = analysis.get("severity", "medium").capitalize()
    sev_color = {"High": RED, "Medium": YELLOW, "Low": GREEN}.get(sev, MUTED)
    sev_badge = (
        f'<span style="display:inline-block;background:{sev_color}22;color:{sev_color};'
        f'border:1px solid {sev_color}55;border-radius:4px;padding:2px 8px;'
        f'font-size:11px;font-weight:700;letter-spacing:1px;font-family:monospace;">{sev.upper()}</span>'
    )

    # False Positive Risk — inverted traffic light, how noisy the rule might be
    fp       = analysis.get("false_positive_risk", "medium").capitalize()
    fp_color = {"Low": GREEN, "Medium": YELLOW, "High": RED}.get(fp, MUTED)
    fp_badge = (
        f'<span style="display:inline-block;background:{fp_color}22;color:{fp_color};'
        f'border:1px solid {fp_color}55;border-radius:4px;padding:2px 8px;'
        f'font-size:11px;font-weight:700;letter-spacing:1px;font-family:monospace;">{fp.upper()}</span>'
    )

    medium_note = ""
    if conf == "Medium":
        medium_note = f"""<tr><td style="padding:0 36px 20px;">
  <p style="margin:0;padding:12px 14px;background:{YELLOW}15;border:1px solid {YELLOW}44;
     border-radius:6px;font-size:13px;color:{YELLOW};line-height:1.6;">
    This rule was deployed at medium confidence. Review it in Kibana before relying on it in production.
  </p>
</td></tr>"""

    content = f"""
<tr><td style="padding:20px 36px;">
  <p style="margin:0;font-size:13px;color:{MUTED};">{now}</p>
  <h1 style="margin:6px 0 0;font-size:20px;font-weight:700;color:{TEXT};">Detection Rule Deployed &nbsp;{sev_badge}</h1>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;padding:14px 16px;
     background:{BG};border-left:3px solid {GREEN};border-radius:0 6px 6px 0;">
    {analysis.get("plain_english_summary","")}
  </p>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  <table width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {BORDER};border-radius:6px;overflow:hidden;background:{BG};">
  <tr>
    <td style="padding:12px 8px;border-right:1px solid {BORDER};text-align:center;">
      <p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Technique</p>
      <p style="margin:0;font-size:13px;font-weight:700;color:{GREEN};font-family:monospace;">{analysis["technique_id"]}</p>
    </td>
    <td style="padding:12px 8px;border-right:1px solid {BORDER};text-align:center;">
      <p style="margin:0 0 5px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Severity</p>
      <p style="margin:0;">{sev_badge}</p>
    </td>
    <td style="padding:12px 8px;border-right:1px solid {BORDER};text-align:center;">
      <p style="margin:0 0 5px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Confidence</p>
      <p style="margin:0;">{conf_badge}</p>
    </td>
    <td style="padding:12px 8px;border-right:1px solid {BORDER};text-align:center;">
      <p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Tactic</p>
      <p style="margin:0;font-size:11px;font-weight:600;color:{TEXT};">{analysis["tactic"].title()}</p>
    </td>
    <td style="padding:12px 8px;text-align:center;">
      <p style="margin:0 0 5px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">FP Risk</p>
      <p style="margin:0;">{fp_badge}</p>
    </td>
  </tr>
  </table>
</td></tr>

{medium_note}

<tr><td style="padding:0 36px 20px;">
  {_section_label("ATT&amp;CK Coverage")}
  <p style="margin:0 0 6px;font-size:14px;line-height:1;">{bar} <span style="color:{TEXT};font-weight:600;">{pct}%</span></p>
  <p style="margin:0;font-size:12px;color:{MUTED};">
    {covered} of {total} attack categories have at least one detection rule
  </p>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("Why This Was Flagged")}
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;">{analysis.get("reasoning","")}</p>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("The 3 Strongest Signals")}
  <table width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {BORDER};border-radius:6px;overflow:hidden;background:{BG};">
  {indicators_html}
  </table>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("What the Rule Watches For")}
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;">{analysis.get("detection_focus","")}</p>
</td></tr>

<tr><td style="padding:0 36px 28px;">
  {_section_label("Recommended Next Step")}
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;padding:14px 16px;
     background:{GREEN_D};border:1px solid {GREEN}44;border-radius:6px;">
    {analysis.get("next_simulation","")}
  </p>
</td></tr>

<tr><td style="padding:0 36px 28px;">
  <table cellpadding="0" cellspacing="0"><tr>
    <td>
      <a href="https://github.com/1xLoZec/detection-lab/actions"
         style="display:inline-block;background:{GREEN};color:#000000;text-decoration:none;
                padding:10px 20px;border-radius:6px;font-size:13px;font-weight:700;">
        CI/CD Pipeline
      </a>
    </td>
  </tr></table>
</td></tr>
"""

    footer = (
        f''
    )

    send_email(
        f"New Detection Rule — {analysis['technique_id']} {analysis['technique_name']}",
        _wrapper(content, footer)
    )


# ── Email: nothing new ─────────────────────────────────────────────────────────
def email_nothing_new(events_count, lookback, analysis, seen):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    covered, total, pct, _ = coverage_stats(seen)
    bar = _bar(pct)

    reason   = analysis.get("skip_reason") or "This technique already has a detection rule."
    next_sim = analysis.get("next_simulation","")

    covered_rows = "".join(
        f'<tr><td style="padding:7px 14px;font-size:12px;color:{MUTED};font-family:monospace;'
        f'border-bottom:1px solid {BORDER};">{t} — {seen[t].get("technique_name","")}</td></tr>'
        for t in seen
    ) or f'<tr><td style="padding:12px 14px;font-size:13px;color:{FAINT};">None yet.</td></tr>'

    content = f"""
<tr><td style="padding:20px 36px;">
  <p style="margin:0;font-size:13px;color:{MUTED};">{now}</p>
  <h1 style="margin:6px 0 0;font-size:20px;font-weight:700;color:{TEXT};">Hunt Complete</h1>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;">
    Reviewed {events_count} events from the last {lookback} minutes. {reason} No new rule was generated.
  </p>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("ATT&amp;CK Coverage")}
  <p style="margin:0 0 6px;font-size:14px;">{bar} <span style="color:{TEXT};font-weight:600;">{pct}%</span></p>
  <p style="margin:0;font-size:12px;color:{MUTED};">
    {covered} of {total} attack categories covered &nbsp;·&nbsp; {len(seen)} techniques in library
  </p>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("Recommended Next Step")}
  <p style="margin:0;font-size:14px;color:{TEXT};padding:14px 16px;
     background:{GREEN_D};border:1px solid {GREEN}44;border-radius:6px;line-height:1.7;">
    {_fmt_next(next_sim)}
  </p>
</td></tr>

<tr><td style="padding:0 36px 28px;">
  {_section_label("Techniques Already Covered")}
  <table width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {BORDER};border-radius:6px;overflow:hidden;background:{BG};">
  {covered_rows}
  </table>
</td></tr>
"""
    send_email("💧 h4voc_water — Hunt complete — no new techniques found", _wrapper(content))


# ── Email: weekly digest ───────────────────────────────────────────────────────
def email_weekly_digest(seen, log):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y")
    covered, total, pct, uncovered = coverage_stats(seen)
    bar = _bar(pct)

    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    week_log = [e for e in log if datetime.fromisoformat(e["timestamp"]) > week_ago]
    deployed = [e for e in week_log if e.get("result") == "deployed"]

    deployed_rows = "".join(
        f'<tr>'
        f'<td style="padding:8px 14px;font-size:12px;color:{GREEN};font-family:monospace;'
        f'border-bottom:1px solid {BORDER};">{e["technique_id"]}</td>'
        f'<td style="padding:8px 14px;font-size:13px;color:{TEXT};border-bottom:1px solid {BORDER};">{e["technique_name"]}</td>'
        f'<td style="padding:8px 14px;font-size:11px;color:{MUTED};border-bottom:1px solid {BORDER};text-align:right;">{e["confidence"].upper()}</td>'
        f'</tr>'
        for e in deployed
    ) or f'<tr><td colspan="3" style="padding:12px 14px;font-size:13px;color:{FAINT};">No rules deployed this week.</td></tr>'

    uncovered_tags = "".join(
        f'<span style="display:inline-block;margin:3px;padding:4px 10px;background:{BG};'
        f'border:1px solid {BORDER};border-radius:4px;font-size:12px;color:{MUTED};">'
        f'{t.replace("-"," ").title()}</span>'
        for t in uncovered
    ) or f'<span style="font-size:13px;color:{GREEN};">All major tactics covered.</span>'

    content = f"""
<tr><td style="padding:20px 36px;">
  <p style="margin:0;font-size:13px;color:{MUTED};">Week ending {now}</p>
  <h1 style="margin:6px 0 0;font-size:20px;font-weight:700;color:{TEXT};">Weekly Detection Report</h1>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  <table width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {BORDER};border-radius:6px;overflow:hidden;background:{BG};">
  <tr>
    <td style="padding:18px;text-align:center;border-right:1px solid {BORDER};">
      <p style="margin:0;font-size:30px;font-weight:700;color:{GREEN};">{len(deployed)}</p>
      <p style="margin:4px 0 0;font-size:11px;color:{MUTED};text-transform:uppercase;letter-spacing:1px;">Rules Deployed</p>
    </td>
    <td style="padding:18px;text-align:center;border-right:1px solid {BORDER};">
      <p style="margin:0;font-size:30px;font-weight:700;color:{TEXT};">{len(week_log)}</p>
      <p style="margin:4px 0 0;font-size:11px;color:{MUTED};text-transform:uppercase;letter-spacing:1px;">Hunts Run</p>
    </td>
    <td style="padding:18px;text-align:center;">
      <p style="margin:0;font-size:30px;font-weight:700;color:{GREEN};">{pct}%</p>
      <p style="margin:4px 0 0;font-size:11px;color:{MUTED};text-transform:uppercase;letter-spacing:1px;">Coverage</p>
    </td>
  </tr>
  </table>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("Overall Coverage")}
  <p style="margin:0 0 6px;font-size:14px;">{bar} <span style="color:{TEXT};font-weight:600;">{pct}%</span></p>
  <p style="margin:0;font-size:12px;color:{MUTED};">{covered} of {total} attack categories &nbsp;·&nbsp; {len(seen)} techniques</p>
</td></tr>

<tr><td style="padding:0 36px 20px;">
  {_section_label("Rules Deployed This Week")}
  <table width="100%" cellpadding="0" cellspacing="0"
         style="border:1px solid {BORDER};border-radius:6px;overflow:hidden;background:{BG};">
  {deployed_rows}
  </table>
</td></tr>

<tr><td style="padding:0 36px 28px;">
  {_section_label("Attack Categories Without Coverage")}
  <div>{uncovered_tags}</div>
</td></tr>
"""
    send_email(f"💧 h4voc_water — Weekly Report — {pct}% coverage", _wrapper(content))


# ── Email: stopped ─────────────────────────────────────────────────────────────
def email_stopped():
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    content = f"""
<tr><td style="padding:20px 36px;">
  <p style="margin:0;font-size:13px;color:{MUTED};">{now}</p>
  <h1 style="margin:6px 0 0;font-size:20px;font-weight:700;color:{TEXT};">Pipeline Paused</h1>
</td></tr>
<tr><td style="padding:0 36px 28px;">
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;">
    h4voc_water ran but STOP_H4VOC_WATER is set to true in your .env file.
    No data was queried and no rules were generated.
    Set it to false to resume.
  </p>
</td></tr>
"""
    send_email("💧 h4voc_water — Pipeline is paused", _wrapper(content))


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
