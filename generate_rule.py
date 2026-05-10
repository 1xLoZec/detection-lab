#!/usr/bin/env python3
"""
1xLoZec Detection Lab - Automated Sigma Rule Generator
Trigger: h4voc water

Automatically loads credentials from .env file.
Queries Elasticsearch for recent simulation telemetry,
extracts MITRE ATT&CK techniques via Claude,
generates Sigma detection rules, pushes to GitHub,
and sends an HTML executive summary email.
"""

import os
import sys
import json
import uuid
import ssl
import smtplib
import subprocess
import warnings
from datetime import datetime, timezone
from email.message import EmailMessage

import requests
import anthropic
from dotenv import load_dotenv

# Load .env file automatically
load_dotenv()

# Suppress SSL warnings for internal VPN connections
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ─── Configuration ─────────────────────────────────────────────────────────────
ELASTIC_URL      = os.getenv("ELASTIC_URL", "https://10.0.0.1:9200")
ELASTIC_API_KEY  = os.getenv("ELASTIC_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
SIGMA_OUTPUT_DIR = "detections/sigma"
TARGET_HOST      = os.getenv("TARGET_HOST", "wkstn-01")
LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "60"))
GMAIL_FROM       = os.getenv("GMAIL_FROM", "")
GMAIL_TO         = os.getenv("GMAIL_TO", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")

# Sysmon event IDs worth collecting
SYSMON_EVENT_IDS = ["1","3","7","8","10","11","12","13","14","15","17","18","22","23","25"]

# Complete ECS field list for Sysmon events
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
    "source.ip","source.port","network.transport","network.protocol","network.direction",
    "winlog.event_data.ImageLoaded","winlog.event_data.Signed",
    "winlog.event_data.Signature","winlog.event_data.SignatureStatus",
    "file.hash.sha256","file.path","file.name","file.extension","file.directory",
    "winlog.event_data.SourceImage","winlog.event_data.TargetImage",
    "winlog.event_data.StartModule","winlog.event_data.StartFunction",
    "winlog.event_data.GrantedAccess","winlog.event_data.CallTrace",
    "registry.key","registry.value","registry.path","registry.data.strings",
    "registry.data.type","dns.question.name","dns.question.type","dns.answers",
    "winlog.event_data.PipeName","winlog.event_data.TargetFilename",
    "related.hash","related.ip","related.user",
]


def flatten_dict(d, parent_key="", sep="."):
    """Recursively flatten nested dict to dot notation for ES _source responses."""
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


# ─── Elasticsearch Query ────────────────────────────────────────────────────────
def query_elasticsearch():
    headers = {"Content-Type": "application/json"}
    if ELASTIC_API_KEY:
        headers["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"

    # Build host filter — supports wildcard (*) for all hosts
    if TARGET_HOST == "*":
        host_filter = {"match_all": {}}
    else:
        host_filter = {"term": {"host.name": TARGET_HOST}}

    query = {
        "size": 100,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": SYSMON_ECS_FIELDS,
        "query": {
            "bool": {
                "must": [
                    host_filter,
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m", "lte": "now"}}}
                ],
                "filter": [{
                    "bool": {
                        "should": [
                            {"term": {"winlog.channel": "Microsoft-Windows-Sysmon/Operational"}},
                            {"terms": {"event.code": SYSMON_EVENT_IDS}},
                        ]
                    }
                }]
            }
        }
    }

    url = f"{ELASTIC_URL}/logs-*/_search"
    response = requests.post(url, headers=headers, json=query, verify=False, timeout=30)

    if response.status_code != 200:
        print(f"Elasticsearch query failed: {response.status_code} {response.text}")
        sys.exit(1)

    hits = response.json().get("hits", {}).get("hits", [])
    host_desc = "all hosts" if TARGET_HOST == "*" else TARGET_HOST
    print(f"Found {len(hits)} events from {host_desc} in the last {LOOKBACK_MINUTES} minutes")

    if not hits:
        print("No events found. Run an Atomic Red Team simulation first.")
        sys.exit(0)

    return [h["_source"] for h in hits]


# ─── Telemetry Preprocessing ────────────────────────────────────────────────────
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
        "pipe_names": set(), "event_codes": set(), "channels": set(),
        "hosts": set(),
    }

    for event in events:
        code = str(event.get("event.code", ""))
        if code: iocs["event_codes"].add(code)
        if event.get("winlog.channel"): iocs["channels"].add(event["winlog.channel"])
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


# ─── Stage 1: ATT&CK Technique Extraction ──────────────────────────────────────
def extract_attack_technique(iocs, events_count):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = f"""You are a MITRE ATT&CK expert. Analyze these IOCs from {events_count} Windows endpoint events and identify the primary ATT&CK technique.

IOC Summary:
{json.dumps(iocs, indent=2)}

Focus on distinctive indicators. Common system processes like svchost.exe, services.exe are background noise.

Respond with JSON only:
{{
  "technique_id": "T1XXX.XXX",
  "technique_name": "Full Technique Name",
  "tactic": "tactic-name",
  "tactic_id": "TAXXXX",
  "confidence": "high/medium/low",
  "reasoning": "concise explanation",
  "key_indicators": ["3-5 most distinctive IOCs"],
  "detection_focus": "what a detection rule should focus on"
}}"""

    message = client.messages.create(
        model="claude-sonnet-4-6", max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    text = message.content[0].text
    return json.loads(text.replace("```json", "").replace("```", "").strip())


# ─── Stage 2: Sigma Rule Generation ────────────────────────────────────────────
def generate_sigma_rule(iocs, attack_technique):
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    rule_id = str(uuid.uuid4())
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    prompt = f"""You are an expert detection engineer writing production Sigma rules for Elastic SIEM with ECS field names from Sysmon via Elastic Agent.

ATT&CK Context (chain of thought):
- Technique: {attack_technique['technique_id']} - {attack_technique['technique_name']}
- Tactic: {attack_technique['tactic']} ({attack_technique.get('tactic_id', '')})
- Confidence: {attack_technique['confidence']}
- Key indicators: {attack_technique['key_indicators']}
- Detection focus: {attack_technique['detection_focus']}
- Reasoning: {attack_technique['reasoning']}

IOCs (use only the most distinctive):
{json.dumps(iocs, indent=2)}

ECS Field Reference:
- process.name, process.executable, process.command_line
- process.parent.name, process.parent.executable
- event.code, file.path, registry.key, dns.question.name
- destination.ip, destination.port
- winlog.event_data.ImageLoaded, winlog.event_data.GrantedAccess
- winlog.event_data.IntegrityLevel, winlog.event_data.PipeName

Rules:
1. Use ECS field names only
2. Choose the most distinctive IOCs
3. Add meaningful false positive examples
4. Set appropriate severity
5. Use correct logsource for windows sysmon

Required metadata: id: {rule_id}, date: {today}, author: 1xLoZec, status: experimental

Respond with ONLY valid Sigma YAML, no markdown:"""

    message = client.messages.create(
        model="claude-sonnet-4-6", max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    sigma_yaml = message.content[0].text.strip().replace("```yaml", "").replace("```", "").strip()
    return sigma_yaml, rule_id


# ─── Rule Validation ─────────────────────────────────────────────────────────────
def validate_sigma_yaml(sigma_yaml):
    required = ["title:", "id:", "logsource:", "detection:", "condition:"]
    missing = [f for f in required if f not in sigma_yaml]
    if missing:
        print(f"Generated rule missing required fields: {missing}")
        return False
    return True


# ─── Save and Push ───────────────────────────────────────────────────────────────
def save_and_push(sigma_yaml, attack_technique, rule_id):
    technique_id = attack_technique["technique_id"].replace(".", "-")
    technique_name = (
        attack_technique["technique_name"].lower()
        .replace(" ", "-").replace("/", "-")
        .replace("(", "").replace(")", "")
    )
    filename = f"{technique_id}-{technique_name}-autogen.yml"
    filepath = os.path.join(SIGMA_OUTPUT_DIR, filename)
    os.makedirs(SIGMA_OUTPUT_DIR, exist_ok=True)

    with open(filepath, "w") as f:
        f.write(sigma_yaml)
    print(f"Saved rule to: {filepath}")

    try:
        subprocess.run(["git", "add", filepath], check=True, capture_output=True)
        commit_msg = f"auto-generate: {attack_technique['technique_id']} {attack_technique['technique_name']} [{rule_id[:8]}]"
        result = subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
        print(f"Git commit: {result.stdout.strip()}")
        subprocess.run(["git", "pull", "--rebase"], check=True, capture_output=True)
        subprocess.run(["git", "push"], check=True, capture_output=True)
        print("Pushed to GitHub — CI/CD pipeline will validate and deploy to Kibana")
        return filepath
    except subprocess.CalledProcessError as e:
        print(f"Git operation failed: {e}")
        return filepath


# ─── HTML Email Notification ─────────────────────────────────────────────────────
def send_email_report(attack_technique, iocs, sigma_yaml, rule_id, events_count, filepath):
    if not all([GMAIL_FROM, GMAIL_TO, GMAIL_APP_PASSWORD]):
        print("Email credentials not configured — skipping email")
        return

    confidence = attack_technique.get("confidence", "unknown")
    confidence_color = {"high": "#00c853", "medium": "#ffd600", "low": "#ff6d00"}.get(confidence, "#888")

    ioc_rows = ""
    for category, values in iocs.items():
        if values and category not in ["event_codes", "channels"]:
            display = ", ".join(str(v) for v in values[:5])
            if len(values) > 5:
                display += f" (+{len(values)-5} more)"
            ioc_rows += f"<tr><td style='padding:6px 12px;color:#aaa;font-size:12px;'>{category.replace('_', ' ').title()}</td><td style='padding:6px 12px;font-size:12px;font-family:monospace;'>{display}</td></tr>"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    github_url = "https://github.com/1xLoZec/detection-lab/actions"
    kibana_url = "https://1xlozec.com/app/security/rules"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;">
<tr><td align="center" style="padding:40px 20px;">
<table width="620" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;">

<!-- Header -->
<tr><td style="background:linear-gradient(135deg,#1f2937,#111827);padding:32px;border-radius:12px 12px 0 0;text-align:center;">
<div style="font-size:11px;letter-spacing:3px;color:#58a6ff;text-transform:uppercase;margin-bottom:8px;">1xLoZec Detection Lab</div>
<div style="font-size:28px;font-weight:700;color:#e6edf3;">H4VOC WATER</div>
<div style="font-size:13px;color:#8b949e;margin-top:6px;">Automated Sigma Rule Generated</div>
<div style="font-size:11px;color:#6e7681;margin-top:4px;">{now}</div>
</td></tr>

<!-- Technique Banner -->
<tr><td style="padding:24px 32px;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;">
<tr><td style="padding:20px;">
<div style="display:flex;align-items:center;margin-bottom:12px;">
<span style="background:{confidence_color}22;color:{confidence_color};border:1px solid {confidence_color};border-radius:20px;padding:3px 12px;font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;">{confidence} confidence</span>
</div>
<div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;">MITRE ATT&CK Technique</div>
<div style="font-size:22px;font-weight:700;color:#58a6ff;margin:6px 0;">{attack_technique['technique_id']}</div>
<div style="font-size:16px;color:#e6edf3;margin-bottom:8px;">{attack_technique['technique_name']}</div>
<div style="font-size:12px;color:#8b949e;">Tactic: <span style="color:#e6edf3;">{attack_technique['tactic'].title()}</span> &nbsp;|&nbsp; Events analyzed: <span style="color:#e6edf3;">{events_count}</span></div>
</td></tr>
</table>
</td></tr>

<!-- Reasoning -->
<tr><td style="padding:0 32px 24px;">
<div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">AI Reasoning</div>
<div style="background:#0d1117;border-left:3px solid #58a6ff;padding:16px;border-radius:0 8px 8px 0;font-size:13px;color:#c9d1d9;line-height:1.6;">
{attack_technique.get('reasoning', 'N/A')}
</div>
</td></tr>

<!-- Detection Focus -->
<tr><td style="padding:0 32px 24px;">
<div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;">Detection Focus</div>
<div style="background:#0d1117;border-left:3px solid #3fb950;padding:16px;border-radius:0 8px 8px 0;font-size:13px;color:#c9d1d9;line-height:1.6;">
{attack_technique.get('detection_focus', 'N/A')}
</div>
</td></tr>

<!-- Key Indicators -->
<tr><td style="padding:0 32px 24px;">
<div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Key Indicators</div>
{''.join(f'<div style="background:#0d1117;border-radius:6px;padding:8px 12px;margin-bottom:6px;font-size:12px;font-family:monospace;color:#f0883e;">⚡ {ind}</div>' for ind in attack_technique.get('key_indicators', []))}
</td></tr>

<!-- IOC Summary -->
<tr><td style="padding:0 32px 24px;">
<div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">IOC Summary ({len(iocs)} categories)</div>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;border-radius:8px;border:1px solid #30363d;">
{ioc_rows}
</table>
</td></tr>

<!-- Generated Sigma Rule -->
<tr><td style="padding:0 32px 24px;">
<div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Generated Sigma Rule</div>
<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;padding:20px;font-family:monospace;font-size:11px;color:#c9d1d9;white-space:pre-wrap;line-height:1.6;overflow-x:auto;">{sigma_yaml}</div>
</td></tr>

<!-- Actions -->
<tr><td style="padding:0 32px 32px;">
<div style="font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">Next Steps</div>
<table cellpadding="0" cellspacing="0">
<tr>
<td style="padding-right:12px;"><a href="{github_url}" style="background:#238636;color:#fff;text-decoration:none;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;display:inline-block;">View CI/CD Pipeline</a></td>
<td><a href="{kibana_url}" style="background:#1f6feb;color:#fff;text-decoration:none;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;display:inline-block;">View Kibana Rules</a></td>
</tr>
</table>
<div style="margin-top:16px;font-size:12px;color:#6e7681;">Rule ID: {rule_id} &nbsp;|&nbsp; File: {os.path.basename(filepath) if filepath else 'N/A'}</div>
<div style="font-size:12px;color:#6e7681;margin-top:4px;">CI/CD: Ollama + Claude + Gemini validation → Kibana auto-deployment</div>
</td></tr>

<!-- Footer -->
<tr><td style="background:#0d1117;border-radius:0 0 12px 12px;padding:20px 32px;text-align:center;border-top:1px solid #30363d;">
<div style="font-size:11px;color:#6e7681;">1xLoZec Detection Lab &nbsp;•&nbsp; Automated Detection Engineering &nbsp;•&nbsp; {now[:10]}</div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    try:
        msg = EmailMessage()
        msg["Subject"] = f"[H4VOC] {attack_technique['technique_id']} — {attack_technique['technique_name']} ({confidence.upper()} confidence)"
        msg["From"] = GMAIL_FROM
        msg["To"] = GMAIL_TO
        msg.set_content("HTML email — view in a modern email client.")
        msg.add_alternative(html, subtype="html")

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(GMAIL_FROM, GMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"Email sent to {GMAIL_TO}")
    except Exception as e:
        print(f"Email failed: {e}")


# ─── Main ─────────────────────────────────────────────────────────────────────────
def main():
    if not ANTHROPIC_API_KEY:
        print("Error: ANTHROPIC_API_KEY not set. Check your .env file.")
        sys.exit(1)

    host_desc = "all hosts" if TARGET_HOST == "*" else TARGET_HOST
    print("=" * 60)
    print("H4VOC WATER — 1xLoZec Automated Sigma Rule Generator")
    print(f"Target: {host_desc} | Lookback: {LOOKBACK_MINUTES} minutes")
    print("=" * 60)

    print(f"\n[1/5] Querying Elasticsearch...")
    events = query_elasticsearch()

    print(f"\n[2/5] Preprocessing {len(events)} events into IOC summary...")
    iocs = preprocess_events(events)
    for category, values in iocs.items():
        if values:
            display = values[:5]
            suffix = f" (+{len(values)-5} more)" if len(values) > 5 else ""
            print(f"  {category}: {display}{suffix}")

    print(f"\n[3/5] Extracting ATT&CK technique via Claude (Stage 1)...")
    attack_technique = extract_attack_technique(iocs, len(events))
    print(f"  Technique:  {attack_technique['technique_id']} — {attack_technique['technique_name']}")
    print(f"  Tactic:     {attack_technique['tactic']}")
    print(f"  Confidence: {attack_technique['confidence']}")
    print(f"  Focus:      {attack_technique['detection_focus']}")

    print(f"\n[4/5] Generating Sigma rule via Claude (Stage 2 with ATT&CK chain of thought)...")
    sigma_yaml, rule_id = generate_sigma_rule(iocs, attack_technique)

    if not validate_sigma_yaml(sigma_yaml):
        print("Generated rule failed structural validation.")
        sys.exit(1)

    print(f"  Rule ID: {rule_id}")
    print("\nGenerated Sigma Rule:")
    print("-" * 60)
    print(sigma_yaml)
    print("-" * 60)

    print(f"\n[5/5] Saving, pushing to GitHub, and sending email report...")
    filepath = save_and_push(sigma_yaml, attack_technique, rule_id)
    send_email_report(attack_technique, iocs, sigma_yaml, rule_id, len(events), filepath)

    print("\n" + "=" * 60)
    print("H4VOC WATER — Complete.")
    print(f"Technique: {attack_technique['technique_id']} — {attack_technique['technique_name']}")
    print(f"Confidence: {attack_technique['confidence']}")
    print("CI/CD: Ollama + Claude + Gemini → Kibana auto-deployment")
    print(f"Email: {GMAIL_TO}")
    print("=" * 60)


if __name__ == "__main__":
    main()
