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

# All 14 major ATT&CK tactics for coverage tracking
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


# ── State Management ───────────────────────────────────────────────────────────
def load_state():
    STATE_DIR.mkdir(exist_ok=True)
    seen_file   = STATE_DIR / "seen_techniques.json"
    last_file   = STATE_DIR / "last_run.json"
    log_file    = STATE_DIR / "hunt_log.json"
    digest_file = STATE_DIR / "weekly_digest.json"

    seen   = json.loads(seen_file.read_text())   if seen_file.exists()   else {}
    last   = json.loads(last_file.read_text())   if last_file.exists()   else {}
    log    = json.loads(log_file.read_text())    if log_file.exists()    else []
    digest = json.loads(digest_file.read_text()) if digest_file.exists() else {"week_start": None, "entries": []}
    return seen, last, log, digest


def save_state(seen, last, log, digest):
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "seen_techniques.json").write_text(json.dumps(seen, indent=2))
    (STATE_DIR / "last_run.json").write_text(json.dumps(last, indent=2))
    (STATE_DIR / "hunt_log.json").write_text(json.dumps(log, indent=2))
    (STATE_DIR / "weekly_digest.json").write_text(json.dumps(digest, indent=2))


def git_push_state():
    """Commit state files to GitHub so coverage memory persists across machines."""
    try:
        subprocess.run(["git", "add", "state/"], check=True, capture_output=True)
        result = subprocess.run(
            ["git", "commit", "-m", "update: h4voc_water state"],
            capture_output=True, text=True
        )
        if "nothing to commit" not in result.stdout:
            subprocess.run(["git", "pull", "--rebase"], check=True, capture_output=True)
            subprocess.run(["git", "push"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pass  # State push is best-effort


def coverage_stats(seen):
    """Calculate tactic coverage as a percentage and simple progress bar."""
    covered_tactics = set()
    for tech_data in seen.values():
        tactic = tech_data.get("tactic", "")
        if tactic:
            covered_tactics.add(tactic)

    covered = len(covered_tactics)
    total = len(ALL_TACTICS)
    pct = int((covered / total) * 100) if total > 0 else 0

    filled = int(pct / 5)
    bar = "█" * filled + "░" * (20 - filled)

    uncovered = [t for t in ALL_TACTICS if t not in covered_tactics]
    return covered, total, pct, bar, covered_tactics, uncovered


def should_send_weekly_digest(digest, now_ts):
    """Check if a weekly digest is due (Sunday, and at least 6 days since last one)."""
    now = datetime.now(timezone.utc)
    if now.weekday() != 6:  # 6 = Sunday
        return False
    week_start = digest.get("week_start")
    if not week_start:
        return True
    last_digest = datetime.fromisoformat(week_start)
    return (now - last_digest).days >= 6


# ── Helper ─────────────────────────────────────────────────────────────────────
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
        "query": {
            "bool": {
                "must": [
                    host_filter,
                    {"range": {"@timestamp": {"gte": f"now-{lookback_minutes}m", "lte": "now"}}}
                ],
                "filter": [{"bool": {"should": [
                    {"term": {"winlog.channel": "Microsoft-Windows-Sysmon/Operational"}},
                    {"terms": {"event.code": SYSMON_EVENT_IDS}},
                ]}}]
            }
        }
    }

    response = requests.post(
        f"{ELASTIC_URL}/logs-*/_search",
        headers=headers, json=query, verify=False, timeout=30
    )

    if response.status_code != 200:
        print(f"Elasticsearch error: {response.status_code}")
        return []

    hits = response.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


# ── Preprocessing ──────────────────────────────────────────────────────────────
def preprocess_events(events):
    events = [flatten_dict(e) for e in events]
    iocs = {
        "processes": set(), "parent_processes": set(), "command_lines": set(),
        "process_hashes_sha256": set(), "original_filenames": set(),
        "integrity_levels": set(), "users": set(),
        "destination_ips": set(), "destination_ports": set(),
        "destination_domains": set(), "protocols": set(),
        "file_paths": set(), "file_extensions": set(),
        "loaded_images": set(), "unsigned_images": set(),
        "registry_keys": set(), "registry_values": set(),
        "dns_queries": set(), "remote_thread_targets": set(),
        "process_access_targets": set(), "granted_access_masks": set(),
        "pipe_names": set(), "event_codes": set(), "hosts": set(),
    }

    for event in events:
        code = str(event.get("event.code", ""))
        if code: iocs["event_codes"].add(code)
        if event.get("host.name"): iocs["hosts"].add(event["host.name"])
        if event.get("process.name"): iocs["processes"].add(event["process.name"])
        if event.get("process.parent.name"): iocs["parent_processes"].add(event["process.parent.name"])
        if event.get("process.command_line") and len(str(event["process.command_line"])) < 500:
            iocs["command_lines"].add(str(event["process.command_line"]))
        if event.get("process.hash.sha256"): iocs["process_hashes_sha256"].add(event["process.hash.sha256"])
        if event.get("process.pe.original_file_name"): iocs["original_filenames"].add(event["process.pe.original_file_name"])
        if event.get("winlog.event_data.IntegrityLevel"): iocs["integrity_levels"].add(event["winlog.event_data.IntegrityLevel"])
        if event.get("user.name"): iocs["users"].add(event["user.name"])
        if event.get("destination.ip"): iocs["destination_ips"].add(event["destination.ip"])
        if event.get("destination.port"): iocs["destination_ports"].add(str(event["destination.port"]))
        if event.get("destination.domain"): iocs["destination_domains"].add(event["destination.domain"])
        if event.get("network.transport"): iocs["protocols"].add(event["network.transport"])
        if event.get("winlog.event_data.ImageLoaded"):
            iocs["loaded_images"].add(event["winlog.event_data.ImageLoaded"].split("\\")[-1])
            if event.get("winlog.event_data.Signed") == "false":
                iocs["unsigned_images"].add(event["winlog.event_data.ImageLoaded"])
        if event.get("winlog.event_data.TargetFilename"): iocs["file_paths"].add(event["winlog.event_data.TargetFilename"])
        if event.get("file.path"): iocs["file_paths"].add(event["file.path"])
        if event.get("file.extension"): iocs["file_extensions"].add(event["file.extension"])
        if event.get("registry.key"): iocs["registry_keys"].add(event["registry.key"])
        if event.get("registry.value"): iocs["registry_values"].add(event["registry.value"])
        if event.get("dns.question.name"): iocs["dns_queries"].add(event["dns.question.name"])
        if event.get("winlog.event_data.TargetImage"):
            target = event["winlog.event_data.TargetImage"].split("\\")[-1]
            if code == "8": iocs["remote_thread_targets"].add(target)
            if code == "10": iocs["process_access_targets"].add(target)
        if event.get("winlog.event_data.GrantedAccess"): iocs["granted_access_masks"].add(event["winlog.event_data.GrantedAccess"])
        if event.get("winlog.event_data.PipeName"): iocs["pipe_names"].add(event["winlog.event_data.PipeName"])

    return {k: sorted(list(v)) for k, v in iocs.items() if v}


# ── Stage 1: Claude decides everything ────────────────────────────────────────
def analyze_with_claude(iocs, events_count, seen_techniques, lookback_used):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    seen_list = list(seen_techniques.keys()) if seen_techniques else []

    prompt = f"""You are a detection engineer analyzing Windows endpoint telemetry. Your job is to decide what to do next.

You analyzed {events_count} events from the last {lookback_used} minutes.

IOC Summary:
{json.dumps(iocs, indent=2)}

Techniques already covered (skip these):
{json.dumps(seen_list)}

Make these decisions and return them as JSON only:

1. What ATT&CK technique do you see in this data?
2. Is this technique already covered? Check the list above.
3. How confident are you — high, medium, or low?
   High means you are certain based on clear distinctive indicators.
   Medium means the indicators are present but could have other explanations.
   Low means the data is too noisy or ambiguous to be sure.
4. What simulation should the analyst run next to fill a gap in coverage?

Return JSON only:
{{
  "technique_id": "T1XXX.XXX",
  "technique_name": "Full Technique Name",
  "tactic": "tactic-name",
  "already_covered": true or false,
  "confidence": "high" or "medium" or "low",
  "reasoning": "two sentences explaining what you saw and why you identified this technique",
  "key_indicators": ["the 3 most distinctive things you saw"],
  "detection_focus": "one sentence on what a rule should specifically look for",
  "next_simulation": "T1XXX — Technique Name — one sentence on why this gap matters",
  "skip_reason": "fill this in only if already_covered is true, otherwise leave empty"
}}"""

    message = client.messages.create(
        model="claude-sonnet-4-6", max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    text = message.content[0].text
    return json.loads(text.replace("```json", "").replace("```", "").strip())


# ── Stage 2: Generate Sigma Rule ───────────────────────────────────────────────
def generate_sigma_rule(iocs, analysis):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    rule_id = str(uuid.uuid4())
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    prompt = f"""You are a detection engineer writing a Sigma rule for Elastic SIEM with Sysmon data using ECS field names.

ATT&CK Technique: {analysis['technique_id']} — {analysis['technique_name']}
Tactic: {analysis['tactic']}
Detection focus: {analysis['detection_focus']}
Key indicators: {analysis['key_indicators']}
Reasoning: {analysis['reasoning']}

IOCs from telemetry:
{json.dumps(iocs, indent=2)}

ECS field names to use:
process.name, process.executable, process.command_line, process.parent.name,
process.parent.executable, event.code, file.path, registry.key,
dns.question.name, destination.ip, destination.port,
winlog.event_data.ImageLoaded, winlog.event_data.GrantedAccess,
winlog.event_data.IntegrityLevel, winlog.event_data.PipeName

Rules: Use ECS field names only. Focus on the most distinctive indicators. Add realistic false positive examples. Set the right severity level.

Required fields: id: {rule_id}, date: {today}, author: 1xLoZec, status: experimental

Return valid Sigma YAML only. No markdown. No explanation."""

    message = client.messages.create(
        model="claude-sonnet-4-6", max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    sigma_yaml = message.content[0].text.strip().replace("```yaml", "").replace("```", "").strip()
    return sigma_yaml, rule_id


# ── Save and Push ──────────────────────────────────────────────────────────────
def save_and_push(sigma_yaml, analysis, rule_id):
    technique_id = analysis["technique_id"].replace(".", "-")
    technique_name = (
        analysis["technique_name"].lower()
        .replace(" ", "-").replace("/", "-")
        .replace("(", "").replace(")", "")
    )
    filename = f"{technique_id}-{technique_name}-autogen.yml"
    filepath = os.path.join(SIGMA_OUTPUT_DIR, filename)
    os.makedirs(SIGMA_OUTPUT_DIR, exist_ok=True)

    with open(filepath, "w") as f:
        f.write(sigma_yaml)

    try:
        subprocess.run(["git", "add", filepath], check=True, capture_output=True)
        commit_msg = f"auto-generate: {analysis['technique_id']} {analysis['technique_name']} [{rule_id[:8]}]"
        result = subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
        print(f"  {result.stdout.strip()}")
        subprocess.run(["git", "pull", "--rebase"], check=True, capture_output=True)
        subprocess.run(["git", "push"], check=True, capture_output=True)
        print("  Pushed to GitHub. CI/CD pipeline is validating and deploying to Kibana.")
        return filepath
    except subprocess.CalledProcessError as e:
        print(f"  Git failed: {e}")
        return filepath


# ── Email ──────────────────────────────────────────────────────────────────────
def send_email(subject, html_body):
    if not all([GMAIL_FROM, GMAIL_TO, GMAIL_APP_PASSWORD]):
        print("  Email not configured. Skipping.")
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = GMAIL_FROM
        msg["To"] = GMAIL_TO
        msg.set_content("Open this email in a modern email client to view the report.")
        msg.add_alternative(html_body, subtype="html")
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(GMAIL_FROM, GMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"  Email sent to {GMAIL_TO}")
    except Exception as e:
        print(f"  Email failed: {e}")


def coverage_bar_html(seen):
    covered, total, pct, bar, covered_tactics, uncovered = coverage_stats(seen)
    filled = int(pct / 5)
    bar_html = (
        '<span style="color:#2ea44f;font-family:monospace;">' + "█" * filled + "</span>" +
        '<span style="color:#30363d;font-family:monospace;">' + "░" * (20 - filled) + "</span>"
    )
    return bar_html, covered, total, pct, uncovered


def email_rule_deployed(analysis, iocs, sigma_yaml, rule_id, events_count, lookback_used, filepath, seen):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    conf = analysis.get("confidence", "unknown").capitalize()
    conf_color = {"High": "#2ea44f", "Medium": "#d4a72c", "Low": "#cf222e"}.get(conf, "#888")

    bar_html, covered, total, pct, uncovered = coverage_bar_html(seen)

    indicators_html = "".join(
        f'<p style="margin:4px 0;font-family:monospace;font-size:13px;color:#e6edf3;'
        f'background:#0d1117;padding:8px 12px;border-radius:6px;">{ind}</p>'
        for ind in analysis.get("key_indicators", [])
    )

    skip_cats = {"event_codes", "channels", "process_hashes_sha256"}
    ioc_rows = ""
    for cat, vals in iocs.items():
        if vals and cat not in skip_cats:
            display = ", ".join(str(v) for v in vals[:4])
            if len(vals) > 4:
                display += f" and {len(vals) - 4} more"
            label = cat.replace("_", " ").title()
            ioc_rows += (
                f'<tr>'
                f'<td style="padding:8px 16px;color:#8b949e;font-size:13px;white-space:nowrap;">{label}</td>'
                f'<td style="padding:8px 16px;font-size:13px;color:#e6edf3;font-family:monospace;">{display}</td>'
                f'</tr>'
            )

    rule_escaped = sigma_yaml.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    medium_note = ""
    if conf == "Medium":
        medium_note = '<p style="margin:0 0 24px;font-size:13px;color:#d4a72c;padding:12px 16px;background:#0d1117;border:1px solid #d4a72c;border-radius:8px;">This rule was deployed at medium confidence. Review it in Kibana before relying on it in production.</p>'

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#e6edf3;">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:32px 16px;">
<table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">

<tr><td style="background:#0d1117;padding:28px 32px;border-bottom:1px solid #30363d;">
  <p style="margin:0;font-size:11px;letter-spacing:2px;color:#58a6ff;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:8px 0 4px;font-size:22px;font-weight:700;">New Detection Rule Deployed</h1>
  <p style="margin:0;font-size:13px;color:#8b949e;">{now}</p>
</td></tr>

<tr><td style="padding:24px 32px;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  <tr><td style="padding:20px 24px;">
    <p style="margin:0 0 4px;font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">ATT&amp;CK Technique</p>
    <p style="margin:0 0 2px;font-size:24px;font-weight:700;color:#58a6ff;">{analysis['technique_id']}</p>
    <p style="margin:0 0 12px;font-size:16px;color:#e6edf3;">{analysis['technique_name']}</p>
    <p style="margin:0;font-size:13px;color:#8b949e;">
      Tactic: <span style="color:#e6edf3;">{analysis['tactic'].title()}</span>
      &nbsp;&nbsp;
      Confidence: <span style="color:{conf_color};font-weight:600;">{conf}</span>
      &nbsp;&nbsp;
      Events reviewed: <span style="color:#e6edf3;">{events_count}</span>
    </p>
  </td></tr>
  </table>

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  <tr><td style="padding:16px 20px;">
    <p style="margin:0 0 8px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">ATT&amp;CK Coverage</p>
    <p style="margin:0 0 6px;font-size:13px;">{bar_html} &nbsp; {pct}%</p>
    <p style="margin:0;font-size:12px;color:#8b949e;">{covered} of {total} major tactics covered &nbsp;&nbsp; {len(seen)} techniques in library</p>
  </td></tr>
  </table>

  {medium_note}

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">What Claude Found</p>
  <p style="margin:0 0 24px;font-size:14px;color:#c9d1d9;line-height:1.6;padding:16px;background:#0d1117;border-left:3px solid #58a6ff;border-radius:0 6px 6px 0;">{analysis.get('reasoning', '')}</p>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">What to Watch For</p>
  <p style="margin:0 0 24px;font-size:14px;color:#c9d1d9;line-height:1.6;padding:16px;background:#0d1117;border-left:3px solid #2ea44f;border-radius:0 6px 6px 0;">{analysis.get('detection_focus', '')}</p>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Key Indicators</p>
  <div style="margin-bottom:24px;">{indicators_html}</div>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Activity Breakdown</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  {ioc_rows}
  </table>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Generated Sigma Rule</p>
  <pre style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:20px;font-size:11px;color:#c9d1d9;white-space:pre-wrap;word-wrap:break-word;margin:0 0 24px;">{rule_escaped}</pre>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">What Happens Next</p>
  <p style="margin:0 0 24px;font-size:13px;color:#c9d1d9;line-height:1.6;">This rule was pushed to GitHub. Ollama, Claude, and Gemini are validating it now. Once it passes, it deploys to Kibana automatically.</p>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Run This Next</p>
  <p style="margin:0 0 24px;font-size:14px;color:#c9d1d9;padding:16px;background:#0d1117;border:1px solid #30363d;border-radius:8px;">{analysis.get('next_simulation', 'No suggestion available.')}</p>

  <table cellpadding="0" cellspacing="0">
  <tr>
    <td style="padding-right:12px;"><a href="https://github.com/1xLoZec/detection-lab/actions" style="background:#238636;color:#fff;text-decoration:none;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;display:inline-block;">CI/CD Pipeline</a></td>
    <td><a href="https://1xlozec.com/app/security/rules" style="background:#1f6feb;color:#fff;text-decoration:none;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;display:inline-block;">Kibana Rules</a></td>
  </tr>
  </table>

</td></tr>

<tr><td style="padding:16px 32px;border-top:1px solid #30363d;background:#0d1117;">
  <p style="margin:0;font-size:11px;color:#6e7681;">Rule ID: {rule_id} &nbsp;&nbsp; File: {os.path.basename(filepath) if filepath else 'N/A'} &nbsp;&nbsp; Lookback: {lookback_used} minutes</p>
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


def email_nothing_new(events_count, lookback_used, analysis, seen):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    bar_html, covered, total, pct, uncovered = coverage_bar_html(seen)

    covered_html = "".join(
        f'<p style="margin:4px 0;font-size:13px;color:#8b949e;">'
        f'{t} — {seen[t].get("technique_name", "")}'
        f'</p>'
        for t in seen
    ) or '<p style="margin:0;font-size:13px;color:#8b949e;">None yet.</p>'

    reason = analysis.get("skip_reason") or "This technique already has a rule in your library."
    next_sim = analysis.get("next_simulation", "No suggestion available.")

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#e6edf3;">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:32px 16px;">
<table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">

<tr><td style="background:#0d1117;padding:28px 32px;border-bottom:1px solid #30363d;">
  <p style="margin:0;font-size:11px;letter-spacing:2px;color:#58a6ff;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:8px 0 4px;font-size:22px;font-weight:700;">Hunt Complete</h1>
  <p style="margin:0;font-size:13px;color:#8b949e;">{now}</p>
</td></tr>

<tr><td style="padding:24px 32px;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  <tr><td style="padding:16px 20px;">
    <p style="margin:0 0 8px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">ATT&amp;CK Coverage</p>
    <p style="margin:0 0 6px;font-size:13px;">{bar_html} &nbsp; {pct}%</p>
    <p style="margin:0;font-size:12px;color:#8b949e;">{covered} of {total} major tactics covered &nbsp;&nbsp; {len(seen)} techniques in library</p>
  </td></tr>
  </table>

  <p style="margin:0 0 24px;font-size:14px;color:#c9d1d9;line-height:1.6;">
    Reviewed {events_count} events from the last {lookback_used} minutes. {reason} No new rule was generated this time.
  </p>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Run This Next</p>
  <p style="margin:0 0 24px;font-size:14px;color:#c9d1d9;padding:16px;background:#0d1117;border:1px solid #30363d;border-radius:8px;">{next_sim}</p>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Techniques Already Covered</p>
  <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;">
    {covered_html}
  </div>

</td></tr>

<tr><td style="padding:16px 32px;border-top:1px solid #30363d;background:#0d1117;">
  <p style="margin:0;font-size:11px;color:#6e7681;">Lookback: {lookback_used} minutes &nbsp;&nbsp; Total techniques covered: {len(seen)}</p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    send_email("[h4voc_water] Hunt complete — no new techniques found", html)


def email_weekly_digest(seen, log):
    now = datetime.now(timezone.utc).strftime("%B %d, %Y")
    bar_html, covered, total, pct, uncovered = coverage_bar_html(seen)

    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    week_entries = [e for e in log if datetime.fromisoformat(e["timestamp"]) > week_ago]
    deployed_this_week = [e for e in week_entries if e.get("result") == "deployed"]
    hunts_this_week = len(week_entries)

    deployed_rows = "".join(
        f'<tr>'
        f'<td style="padding:8px 16px;font-size:13px;color:#58a6ff;font-family:monospace;">{e["technique_id"]}</td>'
        f'<td style="padding:8px 16px;font-size:13px;color:#e6edf3;">{e["technique_name"]}</td>'
        f'<td style="padding:8px 16px;font-size:12px;color:#8b949e;">{e["confidence"].capitalize()}</td>'
        f'</tr>'
        for e in deployed_this_week
    ) or '<tr><td colspan="3" style="padding:12px 16px;font-size:13px;color:#8b949e;">No rules deployed this week.</td></tr>'

    uncovered_html = "".join(
        f'<p style="margin:4px 0;font-size:13px;color:#8b949e;">{t.replace("-", " ").title()}</p>'
        for t in uncovered
    ) or '<p style="margin:0;font-size:13px;color:#2ea44f;">All major tactics covered.</p>'

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#e6edf3;">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:32px 16px;">
<table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">

<tr><td style="background:#0d1117;padding:28px 32px;border-bottom:1px solid #30363d;">
  <p style="margin:0;font-size:11px;letter-spacing:2px;color:#58a6ff;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:8px 0 4px;font-size:22px;font-weight:700;">Weekly Detection Report</h1>
  <p style="margin:0;font-size:13px;color:#8b949e;">Week ending {now}</p>
</td></tr>

<tr><td style="padding:24px 32px;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  <tr>
    <td style="padding:16px 20px;text-align:center;border-right:1px solid #30363d;">
      <p style="margin:0;font-size:28px;font-weight:700;color:#58a6ff;">{len(deployed_this_week)}</p>
      <p style="margin:4px 0 0;font-size:12px;color:#8b949e;">Rules Deployed</p>
    </td>
    <td style="padding:16px 20px;text-align:center;border-right:1px solid #30363d;">
      <p style="margin:0;font-size:28px;font-weight:700;color:#e6edf3;">{hunts_this_week}</p>
      <p style="margin:4px 0 0;font-size:12px;color:#8b949e;">Hunts Run</p>
    </td>
    <td style="padding:16px 20px;text-align:center;">
      <p style="margin:0;font-size:28px;font-weight:700;color:#2ea44f;">{pct}%</p>
      <p style="margin:4px 0 0;font-size:12px;color:#8b949e;">Tactic Coverage</p>
    </td>
  </tr>
  </table>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Overall Coverage</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  <tr><td style="padding:16px 20px;">
    <p style="margin:0 0 6px;font-size:14px;">{bar_html} &nbsp; {pct}%</p>
    <p style="margin:0;font-size:12px;color:#8b949e;">{covered} of {total} major tactics &nbsp;&nbsp; {len(seen)} total techniques</p>
  </td></tr>
  </table>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Rules Deployed This Week</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;margin-bottom:24px;">
  {deployed_rows}
  </table>

  <p style="margin:0 0 6px;font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">Tactics Without Coverage</p>
  <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;">
    {uncovered_html}
  </div>

</td></tr>

<tr><td style="padding:16px 32px;border-top:1px solid #30363d;background:#0d1117;">
  <p style="margin:0;font-size:11px;color:#6e7681;">1xLoZec Detection Lab &nbsp;&nbsp; Weekly digest &nbsp;&nbsp; {now}</p>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    send_email(f"[h4voc_water] Weekly Report — {pct}% tactic coverage", html)


def email_stopped():
    now = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#e6edf3;">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:32px 16px;">
<table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;">
<tr><td style="background:#0d1117;padding:28px 32px;border-bottom:1px solid #30363d;">
  <p style="margin:0;font-size:11px;letter-spacing:2px;color:#cf222e;text-transform:uppercase;">1xLoZec Detection Lab</p>
  <h1 style="margin:8px 0 4px;font-size:22px;font-weight:700;">Pipeline Paused</h1>
  <p style="margin:0;font-size:13px;color:#8b949e;">{now}</p>
</td></tr>
<tr><td style="padding:24px 32px;">
  <p style="margin:0;font-size:14px;color:#c9d1d9;line-height:1.6;">
    h4voc_water ran but STOP_H4VOC_WATER is set to true in your .env file.
    No data was queried and no rules were generated.
    Remove that setting or set it to false to resume.
  </p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""
    send_email("[h4voc_water] Pipeline is paused", html)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("h4voc_water — 1xLoZec Detection Lab")
    print("=" * 60)

    if not ANTHROPIC_API_KEY:
        print("Error: ANTHROPIC_API_KEY not set. Check your .env file.")
        sys.exit(1)

    if STOP_H4VOC_WATER:
        print("Pipeline is paused. STOP_H4VOC_WATER=true in .env")
        email_stopped()
        sys.exit(0)

    seen, last, log, digest = load_state()
    now_ts = datetime.now(timezone.utc).isoformat()

    # Send weekly digest if due
    if should_send_weekly_digest(digest, now_ts):
        print("Sending weekly digest...")
        email_weekly_digest(seen, log)
        digest["week_start"] = now_ts
        digest["entries"] = []

    # Decide lookback window based on last run
    last_run_ts = last.get("timestamp")
    if last_run_ts:
        last_run = datetime.fromisoformat(last_run_ts)
        minutes_since = int((datetime.now(timezone.utc) - last_run).total_seconds() / 60)
        lookback = max(10, min(minutes_since + 5, 1440))
        print(f"Last run was {minutes_since} minutes ago. Looking back {lookback} minutes.")
    else:
        lookback = 60
        print(f"First run. Looking back {lookback} minutes.")

    print(f"\n[1/4] Querying Elasticsearch...")
    events = query_elasticsearch(lookback)
    print(f"  Found {len(events)} events.")

    if not events:
        print("  No events found. Run an Atomic Red Team simulation first.")
        log.append({"timestamp": now_ts, "result": "no_events", "lookback": lookback})
        last["timestamp"] = now_ts
        save_state(seen, last, log, digest)
        git_push_state()
        sys.exit(0)

    print(f"\n[2/4] Preprocessing events...")
    iocs = preprocess_events(events)
    for cat, vals in iocs.items():
        if cat not in {"event_codes", "channels", "process_hashes_sha256"} and vals:
            display = vals[:4]
            suffix = f" (+{len(vals)-4} more)" if len(vals) > 4 else ""
            print(f"  {cat}: {display}{suffix}")

    print(f"\n[3/4] Claude is analyzing...")
    analysis = analyze_with_claude(iocs, len(events), seen, lookback)
    print(f"  Technique:  {analysis['technique_id']} — {analysis['technique_name']}")
    print(f"  Confidence: {analysis['confidence']}")
    print(f"  Covered:    {analysis['already_covered']}")
    print(f"  Reasoning:  {analysis['reasoning']}")

    last["timestamp"] = now_ts

    if analysis["already_covered"] or analysis["confidence"] == "low":
        reason = "already covered" if analysis["already_covered"] else "confidence too low"
        print(f"\n  Skipping rule generation ({reason}).")
        print(f"  Suggested next: {analysis.get('next_simulation', 'N/A')}")
        log.append({
            "timestamp": now_ts,
            "result": reason.replace(" ", "_"),
            "technique_id": analysis["technique_id"],
            "technique_name": analysis["technique_name"],
            "confidence": analysis["confidence"],
            "lookback": lookback,
        })
        save_state(seen, last, log, digest)
        git_push_state()
        email_nothing_new(len(events), lookback, analysis, seen)
        print("\n" + "=" * 60)
        print(f"h4voc_water complete. Nothing new to deploy.")
        _, _, pct, _, _ = coverage_bar_html(seen)
        print(f"Coverage: {pct}% — {len(seen)} techniques in library.")
        print("=" * 60)
        return

    print(f"\n[4/4] Generating and deploying Sigma rule...")
    sigma_yaml, rule_id = generate_sigma_rule(iocs, analysis)

    required = ["title:", "id:", "logsource:", "detection:", "condition:"]
    if not all(f in sigma_yaml for f in required):
        print("  Generated rule failed validation. Skipping.")
        sys.exit(1)

    filepath = save_and_push(sigma_yaml, analysis, rule_id)

    seen[analysis["technique_id"]] = {
        "technique_name": analysis["technique_name"],
        "tactic": analysis["tactic"],
        "rule_id": rule_id,
        "deployed_at": now_ts,
        "confidence": analysis["confidence"],
    }

    log.append({
        "timestamp": now_ts,
        "result": "deployed",
        "technique_id": analysis["technique_id"],
        "technique_name": analysis["technique_name"],
        "confidence": analysis["confidence"],
        "rule_id": rule_id,
        "filepath": filepath,
        "lookback": lookback,
    })

    save_state(seen, last, log, digest)
    git_push_state()
    email_rule_deployed(analysis, iocs, sigma_yaml, rule_id, len(events), lookback, filepath, seen)

    _, _, pct, _, _ = coverage_bar_html(seen)
    print("\n" + "=" * 60)
    print(f"h4voc_water complete.")
    print(f"Technique: {analysis['technique_id']} — {analysis['technique_name']}")
    print(f"Confidence: {analysis['confidence']}")
    print(f"Coverage: {pct}% — {len(seen)} techniques in library.")
    print(f"Next: {analysis.get('next_simulation', 'N/A')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
