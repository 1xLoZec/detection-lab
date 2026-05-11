import sys
import json
import os
import requests
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline


def convert_sigma(rule_path):
    backend = LuceneBackend(processing_pipeline=sysmon_pipeline())
    rules = SigmaCollection.load_ruleset([rule_path])
    result = backend.convert(rules)
    return result[0] if result else None


def parse_llm_response(text):
    try:
        clean = text.replace("```json", "").replace("```", "").strip()
        return json.loads(clean)
    except Exception:
        return {"score": 5, "approve": False, "issues": ["Could not parse response"], "reasoning": text[:200]}


def ask_ollama(rule_text, query):
    prompt = f"""You are a detection engineering expert reviewing a Sigma rule for a home detection lab.
Score this rule 1-10 using these exact criteria:
- 8-10: Valid logsource, correct ECS fields, logical detection condition, ATT&CK tags present, would realistically fire on attacker behavior
- 5-7: Minor issues like slightly broad conditions or missing optional fields, but functionally sound
- 1-4: Wrong field names, impossible logic, would never fire, or is dangerously noisy with no filters

This is a lab environment with Sysmon + Elastic Agent on Windows. Be practical, not academic.
A score of 6+ with approve=true means deploy it. Do not fail rules for being imperfect — fail them only if they are fundamentally broken.

Rule: {rule_text}
Elastic Query: {query}
Respond with JSON only: {{"score": 1-10, "approve": true/false, "issues": [], "reasoning": ""}}"""
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "qwen2.5:14b", "prompt": prompt, "stream": False}
    )
    return parse_llm_response(response.json().get("response", ""))


def ask_claude(rule_text, query):
    prompt = f"""You are a detection engineering expert reviewing a Sigma rule for a home detection lab.
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
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        json={
            "model": "claude-sonnet-4-6",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }
    )
    return parse_llm_response(response.json()["content"][0]["text"])


def ask_gemini(rule_text, query):
    prompt = f"""You are a detection engineering expert reviewing a Sigma rule for a home detection lab.
Score this rule 1-10 using these exact criteria:
- 8-10: Valid logsource, correct ECS fields, logical detection condition, ATT&CK tags present, would realistically fire on attacker behavior
- 5-7: Minor issues like slightly broad conditions or missing optional fields, but functionally sound
- 1-4: Wrong field names, impossible logic, would never fire, or is dangerously noisy with no filters

This is a lab environment with Sysmon + Elastic Agent on Windows. Be practical, not academic.
A score of 6+ with approve=true means deploy it. Do not fail rules for being imperfect — fail them only if they are fundamentally broken.

Rule: {rule_text}
Elastic Query: {query}
Respond with JSON only: {{"score": 1-10, "approve": true/false, "issues": [], "reasoning": ""}}"""
    response = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={os.environ['GEMINI_API_KEY']}",
        json={"contents": [{"parts": [{"text": prompt}]}]}
    )
    resp = response.json()
    if "candidates" not in resp:
        return {"score": 5, "approve": False, "issues": [f"Gemini API error"], "reasoning": str(resp)[:200]}
    return parse_llm_response(resp["candidates"][0]["content"]["parts"][0]["text"])


def main():
    rule_path = sys.argv[1]

    with open(rule_path, "r") as f:
        rule_text = f.read()

    print(f"Converting {rule_path}...")
    query = convert_sigma(rule_path)
    if not query:
        print("FAIL: Could not convert Sigma rule")
        sys.exit(1)

    print(f"Elastic Query: {query}")

    print("Validating with Ollama...")
    ollama_result = ask_ollama(rule_text, query)
    print(f"Ollama: score={ollama_result.get('score')} approve={ollama_result.get('approve')}")

    print("Validating with Claude...")
    claude_result = ask_claude(rule_text, query)
    print(f"Claude: score={claude_result.get('score')} approve={claude_result.get('approve')}")

    print("Validating with Gemini...")
    gemini_result = ask_gemini(rule_text, query)
    print(f"Gemini: score={gemini_result.get('score')} approve={gemini_result.get('approve')}")

    approvals = sum([
        ollama_result.get("approve", False),
        claude_result.get("approve", False),
        gemini_result.get("approve", False)
    ])

    avg_score = (
        ollama_result.get("score", 0) +
        claude_result.get("score", 0) +
        gemini_result.get("score", 0)
    ) / 3

    print(f"\nResults: {approvals}/3 approved, average score: {avg_score:.1f}/10")

    if approvals >= 2 and avg_score >= 6:
        print("PASS: Rule approved for deployment")
        sys.exit(0)
    else:
        print("FAIL: Rule did not pass validation")
        sys.exit(1)


if __name__ == "__main__":
    main()
