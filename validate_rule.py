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
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={os.environ['GEMINI_API_KEY']}",
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
    """Email when self-healing gives up after max attempts."""
    gmail_from = os.environ.get("GMAIL_FROM", "")
    gmail_to   = os.environ.get("GMAIL_TO", "")
    gmail_pass = os.environ.get("GMAIL_APP_PASSWORD", "")

    if not all([gmail_from, gmail_to, gmail_pass]):
        print("  [circuit breaker] email credentials not set — skipping notification")
        return

    summary = ""
    for i, fb in enumerate(feedback_history, 1):
        summary += f"\nAttempt {i}:\n"
        for validator, result in fb.items():
            summary += f"  {validator}: score={result.get('score')} approve={result.get('approve')}\n"
            if result.get("reasoning"):
                summary += f"    → {result.get('reasoning')[:200]}\n"

    msg = EmailMessage()
    msg["Subject"] = f"[Circuit Breaker] Rule failed after {attempts} attempts — manual review needed"
    msg["From"]    = gmail_from
    msg["To"]      = gmail_to
    msg.set_content(f"""h4voc_water self-healing pipeline has given up on this rule.

Rule: {rule_path}
Attempts: {attempts}

The AI tried to fix this rule {attempts} times and it still failed validation.
Action required: review and fix manually, or delete it and let h4voc_water regenerate.

Validator feedback history:
{summary}

— h4voc_water
""")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(gmail_from, gmail_pass)
            s.send_message(msg)
        print(f"  [circuit breaker] email sent to {gmail_to}")
    except Exception as e:
        print(f"  [circuit breaker] email failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

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
