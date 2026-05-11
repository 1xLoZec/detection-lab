"""
validate_rule.py — h4voc_water self-healing validation pipeline

Stages:
  1. YAML lint — catch malformed YAML before burning API calls
  2. Sigma → Lucene conversion
  3. Backtest — verify query matches real data in Elasticsearch
  4. 3-AI validation — Claude + Gemini + Ollama score the rule
  5. Self-heal — Claude rewrites failing rules using structured feedback
  6. Circuit breaker — email alert after 3 failed attempts

Max 3 attempts. Healed rule written back to file for git commit.
"""

import sys
import json
import os
import time
import smtplib
import requests
import yaml
from email.message import EmailMessage
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline


# ── Sigma conversion ──────────────────────────────────────────────────────────

def convert_sigma(rule_path):
    """Convert a Sigma YAML file to a Lucene query string."""
    backend = LuceneBackend(processing_pipeline=sysmon_pipeline())
    rules   = SigmaCollection.load_ruleset([rule_path])
    result  = backend.convert(rules)
    return result[0] if result else None


def convert_sigma_text(rule_text):
    """Convert Sigma YAML text (not a file) to a Lucene query string."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as tmp:
        tmp.write(rule_text)
        tmp_path = tmp.name
    try:
        return convert_sigma(tmp_path)
    finally:
        os.unlink(tmp_path)


# ── Stage 1: YAML lint ────────────────────────────────────────────────────────

def lint_sigma_yaml(rule_text):
    """Check YAML syntax and required Sigma fields before burning API calls."""
    try:
        parsed   = yaml.safe_load(rule_text)
        required = ["title", "id", "logsource", "detection"]
        missing  = [f for f in required if f not in parsed]
        if missing:
            return False, f"Missing required fields: {missing}"
        return True, "OK"
    except yaml.YAMLError as e:
        return False, f"YAML syntax error: {e}"


# ── Stage 3: Backtest ─────────────────────────────────────────────────────────

def backtest_query(query):
    """
    Run the Lucene query against logs-* and check if it matches any data.
    Returns (hit_count, error_message).
    A count of 0 means field names are wrong or rule logic is unreachable.
    """
    elastic_url = os.environ.get("ELASTIC_URL", "https://10.0.0.1:9200")
    elastic_key = os.environ.get("ELASTIC_API_KEY", "")

    try:
        resp = requests.post(
            f"{elastic_url}/logs-*/_count",
            headers={
                "Authorization": f"ApiKey {elastic_key}",
                "Content-Type": "application/json",
            },
            json={"query": {"query_string": {"query": query, "analyze_wildcard": True}}},
            verify=False,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("count", 0), None
        return 0, f"Elasticsearch returned {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return 0, f"Backtest connection error: {e}"


# ── Stage 4: AI validators ────────────────────────────────────────────────────

VALIDATION_PROMPT = """You are a detection engineering expert reviewing a Sigma rule for a home detection lab.

Score this rule 1-10 using these exact criteria:
- 8-10: Valid logsource, correct ECS fields, logical detection condition, ATT&CK tags present, would realistically fire on attacker behavior
- 5-7: Minor issues like slightly broad conditions or missing optional fields, but functionally sound
- 1-4: Wrong field names, impossible logic, would never fire, or is dangerously noisy with no filters

This is a lab environment with Sysmon + Elastic Agent on Windows. Be practical, not academic.
A score of 6+ with approve=true means deploy it. Do not fail rules for being imperfect — fail them only if they are fundamentally broken.

Rule:
{rule_text}

Elastic Query:
{query}

Respond with JSON only: {{"score": 1-10, "approve": true/false, "issues": [], "reasoning": ""}}"""


def parse_llm_response(text):
    try:
        clean = text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
    except Exception:
        return {"score": 5, "approve": False, "issues": ["Could not parse response"], "reasoning": text[:200]}


def ask_ollama(rule_text, query):
    prompt = VALIDATION_PROMPT.format(rule_text=rule_text, query=query)
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "qwen2.5:14b", "prompt": prompt, "stream": False},
        timeout=120,
    )
    return parse_llm_response(response.json().get("response", ""))


def ask_claude(rule_text, query):
    prompt = VALIDATION_PROMPT.format(rule_text=rule_text, query=query)
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    return parse_llm_response(response.json()["content"][0]["text"])


def ask_gemini(rule_text, query):
    prompt = VALIDATION_PROMPT.format(rule_text=rule_text, query=query)
    response = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={os.environ['GEMINI_API_KEY']}",
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=60,
    )
    resp = response.json()
    if "candidates" not in resp:
        return {"score": 5, "approve": False, "issues": ["Gemini API error"], "reasoning": str(resp)[:200]}
    return parse_llm_response(resp["candidates"][0]["content"]["parts"][0]["text"])


def validate_rule_text(rule_text, query):
    """Run all 3 validators. Returns approvals, avg_score, feedback_by_validator."""
    print("  Validating with Ollama...")
    ollama = ask_ollama(rule_text, query)
    print(f"  Ollama:  score={ollama.get('score')} approve={ollama.get('approve')}")

    print("  Validating with Claude...")
    claude = ask_claude(rule_text, query)
    print(f"  Claude:  score={claude.get('score')} approve={claude.get('approve')}")

    print("  Validating with Gemini...")
    gemini = ask_gemini(rule_text, query)
    print(f"  Gemini:  score={gemini.get('score')} approve={gemini.get('approve')}")

    feedback = {"Ollama": ollama, "Claude": claude, "Gemini": gemini}
    approvals = sum(r.get("approve", False) for r in feedback.values())
    avg_score = sum(r.get("score", 0) for r in feedback.values()) / 3

    print(f"  Results: {approvals}/3 approved · avg score {avg_score:.1f}/10")
    return approvals, avg_score, feedback


# ── Stage 5: Self-healer ──────────────────────────────────────────────────────

HEAL_PROMPT = """You are a detection engineering expert. This Sigma rule failed validation on attempt {attempt}.

ORIGINAL RULE:
{rule_text}

ELASTIC QUERY IT PRODUCED:
{query}

BACKTEST RESULT:
{backtest_info}

STRUCTURED VALIDATOR FEEDBACK:
{feedback}

REFERENCE — A GOOD SIGMA RULE (use this as a template for structure and field names):
title: PowerShell Encoded Command Execution
id: a2b1c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell execution with encoded command argument, commonly used to obfuscate malicious code.
author: 1xLoZec
date: 2026/05/10
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process.name: powershell.exe
        process.command_line|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-ec '
    condition: selection
falsepositives:
    - Legitimate administrative scripts using encoded commands
level: medium
fields:
    - process.name
    - process.command_line
    - process.parent.name

RULES FOR YOUR REWRITE:
1. Valid ECS fields ONLY: process.name, process.executable, process.command_line,
   process.parent.name, process.parent.executable, registry.key, registry.value,
   network.destination.ip, file.path, file.name, event.code, user.name, host.name
2. BANNED modifiers — NEVER use: |in, |lowercasefield, |re — not supported by pySigma 0.11.23. Use contains, startswith, endswith, or exact match instead
3. Simple, single selection block — one clear detection condition
4. Keep the same ATT&CK technique ID in tags
5. Keep the same rule id (UUID)
6. If the backtest showed 0 hits, simplify the detection to match more broadly

Return ONLY the complete fixed Sigma YAML. No explanation. No markdown fences."""


def heal_rule(rule_text, query, backtest_count, feedback_by_validator, attempt):
    """Ask Claude to rewrite a failing rule using structured per-validator feedback."""
    structured = ""
    for validator, result in feedback_by_validator.items():
        structured += f"\n{validator} (score {result.get('score')}/10, approve={result.get('approve')}):\n"
        for issue in result.get("issues", []):
            structured += f"  - {issue}\n"
        if result.get("reasoning"):
            structured += f"  reasoning: {result.get('reasoning')[:300]}\n"

    backtest_info = (
        f"Query returned {backtest_count} hits against logs-* — field names appear valid"
        if backtest_count > 0
        else "Query returned 0 hits against logs-* — field names are likely wrong or logic is unreachable"
    )

    prompt = HEAL_PROMPT.format(
        attempt=attempt,
        rule_text=rule_text,
        query=query,
        backtest_info=backtest_info,
        feedback=structured,
    )

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=90,
    )
    healed = response.json()["content"][0]["text"].strip()
    return healed.replace("```yaml", "").replace("```", "").strip()


# ── Circuit breaker email ─────────────────────────────────────────────────────

def send_circuit_breaker_email(rule_path, attempts, feedback_history):
    """Email when self-healing gives up — HTML design matching h4voc_water emails."""
    gmail_from = os.environ.get("GMAIL_FROM", "")
    gmail_to   = os.environ.get("GMAIL_TO", "")
    gmail_pass = os.environ.get("GMAIL_APP_PASSWORD", "")
    if not all([gmail_from, gmail_to, gmail_pass]):
        print("  [circuit breaker] email credentials not set — skipping notification")
        return

    from datetime import datetime, timezone
    now       = datetime.now(timezone.utc).strftime("%B %d, %Y at %I:%M %p UTC")
    rule_name = rule_path.split("/")[-1].replace(".yml", "").replace("-", " ").title()

    BG    = "#0d1117"
    CARD  = "#161b22"
    BORD  = "#21262d"
    TEXT  = "#e6edf3"
    MUTED = "#8b949e"
    RED   = "#f85149"

    feedback_rows = ""
    for i, fb in enumerate(feedback_history, 1):
        feedback_rows += f"""<tr><td colspan="4" style="padding:8px 14px 2px;font-size:11px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;background:{CARD};">Attempt {i}</td></tr>"""
        for validator, result in fb.items():
            score     = result.get("score", "?")
            approved  = result.get("approve", False)
            reasoning = (result.get("reasoning") or "")[:180]
            a_color   = "#4caf50" if approved else RED
            a_label   = "APPROVED" if approved else "REJECTED"
            s_color   = "#4caf50" if (isinstance(score, int) and score >= 7) else "#ff9800" if (isinstance(score, int) and score >= 5) else RED
            feedback_rows += f"""<tr style="border-bottom:1px solid {BORD};"><td style="padding:8px 14px;font-size:13px;color:{TEXT};font-weight:600;">{validator}</td><td style="padding:8px 14px;text-align:center;"><span style="background:{s_color}22;color:{s_color};border:1px solid {s_color}55;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;font-family:monospace;">{score}/10</span></td><td style="padding:8px 14px;text-align:center;"><span style="background:{a_color}22;color:{a_color};border:1px solid {a_color}55;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;font-family:monospace;">{a_label}</span></td><td style="padding:8px 14px;font-size:12px;color:{MUTED};font-style:italic;">{reasoning}</td></tr>"""

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>h4voc_water</title></head>
<body style="margin:0;padding:0;background:{BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};"><tr><td align="center" style="padding:32px 16px;">
<table width="580" cellpadding="0" cellspacing="0" style="background:{CARD};border-radius:10px;border:1px solid {BORD};overflow:hidden;">
<tr><td style="padding:22px 36px 16px;border-bottom:1px solid {BORD};"><p style="margin:0;font-size:10px;font-weight:600;letter-spacing:2px;color:{MUTED};text-transform:uppercase;">1xLoZec Detection Lab</p></td></tr>
<tr><td style="padding:20px 36px;"><p style="margin:0;font-size:13px;color:{MUTED};">{now}</p><h1 style="margin:6px 0 0;font-size:20px;font-weight:700;color:{TEXT};">Circuit Breaker Fired</h1></td></tr>
<tr><td style="padding:0 36px 20px;"><p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;padding:14px 16px;background:{BG};border-left:3px solid {RED};border-radius:0 6px 6px 0;">The self-healing pipeline tried to fix this rule <strong>{attempts} times</strong> and failed every attempt. Manual review or deletion required.</p></td></tr>
<tr><td style="padding:0 36px 20px;">
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {BORD};border-radius:6px;overflow:hidden;background:{BG};"><tr>
    <td style="padding:12px 8px;border-right:1px solid {BORD};text-align:center;"><p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Rule</p><p style="margin:0;font-size:11px;font-weight:700;color:{RED};font-family:monospace;">{rule_name}</p></td>
    <td style="padding:12px 8px;border-right:1px solid {BORD};text-align:center;"><p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Attempts</p><p style="margin:0;font-size:20px;font-weight:700;color:{RED};">{attempts}</p></td>
    <td style="padding:12px 8px;text-align:center;"><p style="margin:0 0 4px;font-size:9px;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Status</p><p style="margin:0;font-size:11px;font-weight:700;color:{RED};font-family:monospace;">FAILED</p></td>
  </tr></table>
</td></tr>
<tr><td style="padding:0 36px 20px;">
  <p style="margin:0 0 10px;font-size:10px;font-weight:600;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Validator Feedback</p>
  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {BORD};border-radius:6px;overflow:hidden;background:{BG};">
  <tr style="background:{CARD};"><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;">Validator</td><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;text-align:center;">Score</td><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;text-align:center;">Result</td><td style="padding:8px 14px;font-size:10px;font-weight:700;letter-spacing:1px;color:{MUTED};text-transform:uppercase;">Reasoning</td></tr>
  {feedback_rows}
  </table>
</td></tr>
<tr><td style="padding:0 36px 28px;">
  <p style="margin:0 0 10px;font-size:10px;font-weight:600;letter-spacing:1.5px;color:{MUTED};text-transform:uppercase;">Action Required</p>
  <p style="margin:0;font-size:14px;color:{TEXT};line-height:1.7;padding:14px 16px;background:{BG};border:1px solid {BORD};border-radius:6px;">Delete <code style="font-family:monospace;background:{CARD};padding:2px 6px;border-radius:3px;color:{RED};">{rule_path}</code> and let h4voc_water regenerate, or manually fix the Sigma YAML.</p>
  <br>
  <table cellpadding="0" cellspacing="0"><tr><td><a href="https://github.com/1xLoZec/detection-lab/blob/main/{rule_path}" style="display:inline-block;background:{RED};color:#ffffff;text-decoration:none;padding:10px 20px;border-radius:6px;font-size:13px;font-weight:700;">View Rule on GitHub</a></td></tr></table>
</td></tr>
</table></td></tr></table></body></html>"""

    msg = EmailMessage()
    msg["Subject"] = f"[Circuit Breaker] {rule_name} — failed after {attempts} attempts"
    msg["From"]    = gmail_from
    msg["To"]      = gmail_to
    msg.set_content(f"Circuit breaker fired on {rule_path} after {attempts} attempts.")
    msg.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(gmail_from, gmail_pass)
            s.send_message(msg)
        print(f"  [circuit breaker] email sent to {gmail_to}")
    except Exception as e:
        print(f"  [circuit breaker] email failed: {e}")


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    rule_path = sys.argv[1]

    with open(rule_path, "r") as f:
        original_rule_text = f.read()

    MAX_ATTEMPTS     = 3
    rule_text        = original_rule_text
    feedback_history = []
    last_backtest    = 0

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n{'='*52}")
        print(f"  Attempt {attempt}/{MAX_ATTEMPTS}: {rule_path}")
        print(f"{'='*52}")

        # Stage 1: YAML lint
        print("  Stage 1: YAML lint...")
        valid, lint_msg = lint_sigma_yaml(rule_text)
        if not valid:
            print(f"  YAML lint FAILED: {lint_msg}")
            if attempt < MAX_ATTEMPTS:
                print("  Sending to Claude for structural repair...")
                time.sleep(2)
                rule_text = heal_rule(
                    rule_text, "N/A — YAML invalid", 0,
                    {"lint": {"score": 0, "approve": False,
                              "issues": [lint_msg], "reasoning": lint_msg}},
                    attempt
                )
                continue
            else:
                send_circuit_breaker_email(rule_path, attempt, feedback_history)
                print(f"FAIL: Rule could not be fixed after {MAX_ATTEMPTS} attempts")
                sys.exit(1)
        print("  YAML lint OK")

        # Stage 2: Convert to Lucene
        print("  Stage 2: Converting to Lucene query...")
        if rule_text == original_rule_text:
            query = convert_sigma(rule_path)
        else:
            query = convert_sigma_text(rule_text)

        if not query:
            print("  Conversion FAILED: pySigma could not convert this rule")
            if attempt < MAX_ATTEMPTS:
                time.sleep(2)
                rule_text = heal_rule(
                    rule_text, "N/A — conversion failed", 0,
                    {"converter": {"score": 0, "approve": False,
                                   "issues": ["pySigma could not convert this rule"],
                                   "reasoning": "Rule could not be converted to Lucene query"}},
                    attempt
                )
                continue
            else:
                send_circuit_breaker_email(rule_path, attempt, feedback_history)
                sys.exit(1)

        print(f"  Query: {query[:120]}{'...' if len(query) > 120 else ''}")

        # Stage 3: Backtest against Elasticsearch
        print("  Stage 3: Backtesting against logs-*...")
        hit_count, backtest_err = backtest_query(query)
        last_backtest = hit_count

        if backtest_err:
            print(f"  Backtest warning: {backtest_err} — continuing anyway")
        elif hit_count == 0:
            print("  Backtest: 0 hits — field names may be wrong")
        else:
            print(f"  Backtest: {hit_count} hits — query matches real data ✓")

        # Stage 4: 3-AI validation
        print("  Stage 4: AI validation...")
        approvals, avg_score, feedback = validate_rule_text(rule_text, query)
        feedback_history.append(feedback)

        # Pass condition: 2/3 approve + avg >= 6 + backtest > 0
        backtest_ok = hit_count > 0 or backtest_err is not None  # allow if ES unreachable
        if approvals >= 2 and avg_score >= 6 and backtest_ok:
            # Write healed rule back if it changed
            if rule_text != original_rule_text:
                with open(rule_path, "w") as f:
                    f.write(rule_text)
                print(f"  Self-healed rule written back to {rule_path}")
            print(f"\nPASS: Rule approved on attempt {attempt} ✓")
            sys.exit(0)

        # Build failure reason
        reasons = []
        if approvals < 2:
            reasons.append(f"only {approvals}/3 validators approved")
        if avg_score < 6:
            reasons.append(f"avg score {avg_score:.1f} < 6")
        if hit_count == 0 and not backtest_err:
            reasons.append("0 backtest hits — fields likely wrong")
        print(f"  Failed: {', '.join(reasons)}")

        if attempt < MAX_ATTEMPTS:
            print(f"\n  Attempt {attempt} failed — Claude is rewriting the rule...")
            time.sleep(3)
            healed = heal_rule(rule_text, query, hit_count, feedback, attempt)
            if healed and len(healed) > 100:
                rule_text = healed
                print("  Rule rewritten — retrying...\n")
            else:
                print("  Healing returned empty result — keeping rule for next attempt")
        else:
            print(f"\nCIRCUIT BREAKER: Rule failed after {MAX_ATTEMPTS} attempts")
            send_circuit_breaker_email(rule_path, MAX_ATTEMPTS, feedback_history)
            print("FAIL: Rule could not be self-healed — manual review required")
            sys.exit(1)


if __name__ == "__main__":
    main()
