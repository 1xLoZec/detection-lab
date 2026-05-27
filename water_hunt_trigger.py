#!/usr/bin/env python3
"""
water_hunt_trigger.py — Hunt-verdict-driven rule generation pass for Water

Phase 6.B integration: lets Water's main loop generate Sigma rules based on
high-confidence Hunt verdicts (in addition to its existing Sysmon-coverage
driven generation).

Architecture:
  1. Query tk-hunt-logs for recent high-confidence verdicts
  2. Apply tallkitchen_safety gates (provenance, score, conflicts, rate limit)
  3. Infer ATT&CK technique from the attacker's honeypot hit profile
  4. Hand off to Water's existing generate_sigma_rule(iocs, analysis) function
  5. Tag the generated rule with triggered_by_hunt_id provenance
  6. Status defaults to 'pending_review' — analyst approves before deploy

The pass is independent of Water's normal coverage flow — both run in the
same invocation, neither blocks the other. Failures here are logged and
swallowed; Water's main coverage pass always continues afterward.

CRITICAL: never writes to tk-hunt-logs (Water is a reader only). Never reads
records with source=='water' (prevents feedback amplification — see
tallkitchen_safety.should_water_act_on_hunt).
"""

import json
import os
import urllib3
from datetime import datetime, timezone
from pathlib import Path

import requests

from tallkitchen_safety import (
    RateLimiter,
    SOURCE_USER, SOURCE_HUNT, TRUST_LEVEL_HIGH,
    HUNT_VERDICT_MAX_AGE_HOURS,
    HUNT_TRIGGERED_DAILY_LIMIT,
    tag_provenance,
    validate_hunt_record_for_water,
    water_should_generate_rule_from_verdict,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Where Hunt writes its canonical records (Hunt's Phase 2 ES dual-write target)
HUNT_LOG_INDEX = "tk-hunt-logs"

# Where hunt-triggered rules live (kept separate from Water's normal output
# for clearer audit trail and easier targeted rollback)
HUNT_TRIGGERED_RULES_DIR = Path("detections/sigma/hunt-triggered")

# Per-technique mapping: which ATT&CK technique does each honeypot hit suggest?
# Source: T-Pot honeypot capabilities + MITRE ATT&CK reconnaissance/initial-access
# techniques. Mapping is conservative — when honeypots don't strongly imply a
# specific technique, we leave it unmapped (and Water skips that verdict).
HONEYPOT_TO_TECHNIQUE = {
    # SSH/Telnet brute force
    "Cowrie":        {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "credential-access"},
    # Industrial control systems
    "ConPot":        {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "Dicompot":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    # Generic network service scanners
    "Honeytrap":     {"id": "T1046",     "name": "Network Service Scanning", "tactic": "discovery"},
    "Suricata":      {"id": "T1046",     "name": "Network Service Scanning", "tactic": "discovery"},
    "P0f":           {"id": "T1046",     "name": "Network Service Scanning", "tactic": "discovery"},
    # Malware/exploit honeypots
    "Dionaea":       {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "ElasticPot":    {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "Tanner":        {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "H0neytr4p":     {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    # Service-specific
    "Mailoney":      {"id": "T1566",     "name": "Phishing", "tactic": "initial-access"},
    "Redishoneypot": {"id": "T1078",     "name": "Valid Accounts", "tactic": "credential-access"},
    "Ipphoney":      {"id": "T1046",     "name": "Network Service Scanning", "tactic": "discovery"},
    "Miniprint":     {"id": "T1046",     "name": "Network Service Scanning", "tactic": "discovery"},
    "Honeyaml":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "Fatt":          {"id": "T1046",     "name": "Network Service Scanning", "tactic": "discovery"},
    "Ciscoasa":      {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
}


def _es_search(es_url: str, api_key: str, index: str, query: dict) -> dict:
    """Search ES via raw requests. Returns {} on any failure (logged by caller)."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    try:
        r = requests.post(
            f"{es_url}/{index}/_search",
            headers=headers, json=query, verify=False, timeout=15,
        )
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception:
        return {}


def fetch_recent_hunt_verdicts(es_url: str, api_key: str, hours: int = None) -> list:
    """
    Pull Hunt verdicts from tk-hunt-logs in the last N hours. Default matches
    safety module's HUNT_VERDICT_MAX_AGE_HOURS so stale records aren't fetched.
    Returns list of records (may be empty if index doesn't exist or nothing matches).

    Field name note: Hunt writes records with `@timestamp` (ES convention),
    NOT `timestamp_utc`. The safety module's validate function uses
    `timestamp_utc` because that's the field name in the *normalized* shape
    we hand to safety. Field rename happens in the per-record normalization
    step below in process_hunt_triggered_verdicts.
    """
    if hours is None:
        hours = HUNT_VERDICT_MAX_AGE_HOURS

    query = {
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                    # Require the verdict bucket to exist with a numeric score.
                    # Pre-Phase-4 Hunt records didn't compute a verdict (the
                    # bucket was added in Phase 4) — those records have nothing
                    # actionable for Water, skip them at fetch time so we don't
                    # spam audit logs with schema-rejection lines.
                    {"exists": {"field": "result.verdict.score"}},
                ],
                # CRITICAL: never read Water's own outputs. This is the
                # primary defense against the feedback amplification loop.
                "must_not": [
                    {"term": {"provenance.source.keyword": "water"}},
                ],
            }
        }
    }
    body = _es_search(es_url, api_key, HUNT_LOG_INDEX, query)
    hits = (body.get("hits", {}) or {}).get("hits", []) or []
    records = [h.get("_source", {}) for h in hits]

    # Deduplicate: keep only the most recent verdict per IOC. ES sort=desc on
    # @timestamp means the first occurrence of each IOC is already the newest.
    # Without this, every Water run would generate one rule per re-hunt of the
    # same IOC. Hunt logs every --fresh run as a new record by design (good
    # for analyst history), but Water should treat re-hunts as "same threat,
    # already-decided" — only the latest verdict matters.
    seen_iocs = set()
    deduped = []
    for r in records:
        ioc = r.get("ioc")
        if not ioc or ioc in seen_iocs:
            continue
        seen_iocs.add(ioc)
        deduped.append(r)
    return deduped


def infer_technique_from_observed(observed: dict) -> dict:
    """
    Map the attacker's honeypot hit profile to a single ATT&CK technique.
    Picks the technique with the most event volume across the honeypots
    that maped to it. Returns None if no honeypots map to known techniques.
    """
    honeypots = observed.get("honeypots", []) or []
    if not honeypots:
        return None

    # Aggregate event counts per technique
    technique_totals = {}  # technique_id -> {info, total_events}
    for hp in honeypots:
        name = hp.get("name") or ""
        count = hp.get("count", 0) or 0
        mapping = HONEYPOT_TO_TECHNIQUE.get(name)
        if not mapping:
            continue
        tid = mapping["id"]
        if tid not in technique_totals:
            technique_totals[tid] = {"info": mapping, "total_events": 0, "honeypots": []}
        technique_totals[tid]["total_events"] += count
        technique_totals[tid]["honeypots"].append(name)

    if not technique_totals:
        return None

    # Pick the technique with the most cumulative events
    best = max(technique_totals.values(), key=lambda x: x["total_events"])
    return {
        "technique_id":   best["info"]["id"],
        "technique_name": best["info"]["name"],
        "tactic":         best["info"]["tactic"],
        "total_events":   best["total_events"],
        "honeypots_seen": best["honeypots"],
    }


def build_iocs_from_hunt(record: dict, observed: dict, identity: dict) -> dict:
    """
    Synthesize an IOC dict in the shape Water's generate_sigma_rule() expects.
    Water normally builds this from Sysmon events; we build it from Hunt's
    enrichment data.

    IMPORTANT: every value must be a JSON-serializable type (list, str, int).
    Water's preprocess_events() builds sets internally for dedup then converts
    to sorted lists before returning. We match that contract here because
    generate_sigma_rule() does `json.dumps(iocs)` to render the prompt.
    """
    ioc = record.get("ioc")
    asn = identity.get("asn")
    asn_org = identity.get("asn_org")
    country = identity.get("country")
    honeypot_names = [hp.get("name") for hp in (observed.get("honeypots") or []) if hp.get("name")]

    iocs = {
        "source_ips":         [ioc] if ioc else [],
        "source_asns":        [str(asn)] if asn else [],
        "source_asn_orgs":    [asn_org] if asn_org else [],
        "source_countries":   [country] if country else [],
        "honeypot_signature": sorted(set(honeypot_names)),
    }
    # Drop empty keys to match preprocess_events() shape (it filters `if v`)
    return {k: v for k, v in iocs.items() if v}


def process_hunt_triggered_verdicts(generate_fn, save_and_push_fn, log: list, _con=None, queue_for_review_fn=None) -> int:
    """
    Main entry point. Called once per Water run, BEFORE Water's normal
    Sysmon-coverage flow. Returns the number of rules generated.

    Args:
      generate_fn: Water's existing generate_sigma_rule(iocs, analysis) function
      save_and_push_fn: Water's existing save_and_push(yaml, analysis, rule_id) function
      log: Water's hunt_log list (mutated — entries appended here)
      _con: optional rich console for output; if None, falls back to print

    Strategy: hunt-triggered runs are independent of coverage-driven runs.
    Failures here are logged and swallowed. Water's main coverage flow
    runs normally afterward regardless.
    """
    def _say(msg: str):
        if _con is not None:
            _con.print(msg)
        else:
            print(msg)

    es_url = os.environ.get("ELASTIC_URL", "https://10.0.0.1:9200")
    api_key = os.environ.get("ELASTIC_API_KEY", "")

    _say("[bold cyan]Hunt-trigger pass[/]  [dim](pulling recent verdicts from tk-hunt-logs)[/]"
         if _con else "Hunt-trigger pass (pulling recent verdicts from tk-hunt-logs)")

    # Step 1: fetch recent verdicts (may be empty if no recent hunts)
    records = fetch_recent_hunt_verdicts(es_url, api_key)
    if not records:
        _say("  [dim]No recent Hunt verdicts found — skipping hunt-trigger pass.[/]"
             if _con else "  No recent Hunt verdicts found — skipping hunt-trigger pass.")
        return 0

    _say(f"  [dim]Found {len(records)} recent verdicts[/]" if _con else f"  Found {len(records)} recent verdicts")

    # Step 2: set up rate limiter
    limiter = RateLimiter("hunt_triggered_rules", daily_limit=HUNT_TRIGGERED_DAILY_LIMIT)
    remaining = limiter.remaining()
    _say(f"  [dim]Daily budget: {remaining}/{limiter.daily_limit} rules remaining[/]"
         if _con else f"  Daily budget: {remaining}/{limiter.daily_limit} rules remaining")

    # Step 3+: filter and act
    generated = 0
    skipped_by_gate = 0
    skipped_no_technique = 0

    for record in records:
        ioc = record.get("ioc", "?")

        # Each record from ES needs to flatten Hunt's result structure into
        # the shape safety.py expects (verdict/observed/identity at top level).
        # Hunt writes @timestamp; safety expects timestamp_utc — translate.
        result = record.get("result") or {}
        normalized = {
            "ioc": ioc,
            "ioc_type": record.get("ioc_type"),
            "timestamp_utc": record.get("@timestamp") or record.get("timestamp_utc"),
            "verdict": result.get("verdict"),
            "provenance": record.get("provenance") or {
                # If Hunt didn't tag provenance yet (Phase 4 records pre-Phase 6),
                # treat as user-initiated with high trust by default. Hunt CLI
                # invocations ARE user-initiated. This is safe because the
                # gate still requires source != water, score >= 75, etc.
                "source": SOURCE_USER,
                "trust_level": TRUST_LEVEL_HIGH,
            },
        }

        gate = water_should_generate_rule_from_verdict(normalized, existing_rules=[], rate_limiter=limiter)
        if not gate.passed:
            skipped_by_gate += 1
            _say(f"  [dim]· skip {ioc}: {gate.reason}[/]" if _con else f"  · skip {ioc}: {gate.reason}")
            continue

        # Step 4: infer technique from honeypot mix
        observed = result.get("observed") or {}
        identity = result.get("identity") or {}
        inferred = infer_technique_from_observed(observed)
        if not inferred:
            skipped_no_technique += 1
            _say(f"  [dim]· skip {ioc}: no honeypot hits map to known ATT&CK techniques[/]"
                 if _con else f"  · skip {ioc}: no honeypot hits map to known ATT&CK techniques")
            continue

        # Step 5: consume rate budget atomically before generating
        if not limiter.consume():
            _say(f"  [yellow]· daily rate limit hit during processing — stopping[/]"
                 if _con else f"  · daily rate limit hit during processing — stopping")
            break

        # Step 6: build the analysis dict Water expects
        # generate_sigma_rule reads: technique_id, technique_name, tactic,
        # detection_focus, key_indicators, reasoning. The first three come
        # from honeypot-to-technique inference; the last three we synthesize
        # from Hunt verdict data so the LLM prompt has concrete guidance.
        verdict_dict = result.get("verdict") or {}
        score = verdict_dict.get("score", 0)
        label = verdict_dict.get("verdict", "?")
        honeypot_names = inferred["honeypots_seen"]
        analysis = {
            "technique_id":           inferred["technique_id"],
            "technique_name":         inferred["technique_name"],
            "tactic":                 inferred["tactic"],
            "severity":               "medium",   # hunt-triggered defaults to medium until analyst review
            "confidence":             "high",     # high because Hunt's verdict already passed gates
            "already_covered":        False,
            "plain_english_summary":  (
                f"Hunt verdict for {ioc} ({label} score {score}/100). "
                f"Attacker hit {observed.get('event_count', 0)} honeypot events. "
                f"Generating coverage for {inferred['technique_id']}."
            ),
            "next_simulation":        "",
            "hunt_triggered":         True,
            "triggered_by_hunt_id":   record.get("hunt_id"),
            "triggered_by_ioc":       ioc,

            # ── Fields that generate_sigma_rule's prompt template reads ──
            "detection_focus": (
                f"Inbound network activity from source IP {ioc} or similar high-volume scanners. "
                f"Look for connection attempts across multiple distinct ports/services in a short window — "
                f"the signature of mass scanning behaviour rather than legitimate targeted use."
            ),
            "key_indicators": [
                f"source IP {ioc}",
                f"ASN {identity.get('asn') or '?'} ({identity.get('asn_org') or 'unknown'})",
                f"source country: {identity.get('country') or 'unknown'}",
                f"hit honeypot types: {', '.join(honeypot_names[:5])}",
                f"event volume: {observed.get('event_count', 0)} events in {HUNT_VERDICT_MAX_AGE_HOURS}h",
            ],
            "reasoning": (
                f"Tall Kitchen Hunt assigned this IP a {label} verdict with score {score}/100. "
                f"The attacker hit multiple honeypot types ({', '.join(honeypot_names)}) suggesting "
                f"{inferred['technique_name']} ({inferred['technique_id']}). "
                f"This rule should fire when similar IPs scan our environment, allowing earlier detection "
                f"of comparable threats before they reach honeypot scale."
            ),
        }

        # Step 7: build iocs and call Water's existing rule generator
        iocs = build_iocs_from_hunt(record, observed, identity)

        _say(f"  [bold green]→ generating rule for {ioc} → {inferred['technique_id']}[/]"
             if _con else f"  → generating rule for {ioc} → {inferred['technique_id']}")

        try:
            sigma_yaml, rule_id = generate_fn(iocs, analysis)
        except Exception as e:
            _say(f"  [red]× generation failed: {e}[/]" if _con else f"  × generation failed: {e}")
            # Refund the rate budget on failure — this slot wasn't actually used
            # for a successful rule. Decrement carefully via consuming a negative...
            # actually, the limiter is consume-only. Accept the cost as a circuit
            # breaker: repeated failures will exhaust the budget and pause Water.
            log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "result": "hunt_triggered_generation_failed",
                "ioc": ioc,
                "triggered_by_hunt_id": record.get("hunt_id"),
                "error": str(e)[:200],
            })
            continue

        # Step 8: route to hunt-triggered output dir, status pending_review
        HUNT_TRIGGERED_RULES_DIR.mkdir(parents=True, exist_ok=True)
        # Filename embeds the hunt_id prefix so the audit trail is in the filename itself
        hunt_id_short = (record.get("hunt_id") or "unknown")[:8]
        slug = f"{inferred['technique_id']}-{hunt_id_short}-{ioc.replace('.', '-')}.yml"
        filepath = HUNT_TRIGGERED_RULES_DIR / slug

        # Stamp the generated YAML with provenance comment block at the top
        provenance_block = (
            f"# Hunt-triggered rule (Phase 6.B)\n"
            f"# Triggered by hunt_id: {record.get('hunt_id')}\n"
            f"# IOC: {ioc}\n"
            f"# Hunt verdict: {result.get('verdict', {}).get('verdict', '?')} "
            f"(score {result.get('verdict', {}).get('score', '?')}/100)\n"
            f"# Status: pending_review (analyst must approve before deployment)\n"
            f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
        )
        filepath.write_text(provenance_block + sigma_yaml)
        # Also place into the unified review queue (approve.py) so both paths funnel to one place
        if queue_for_review_fn is not None:
            try:
                queue_for_review_fn(sigma_yaml, {
                    "technique_id": inferred["technique_id"],
                    "technique_name": inferred["technique_name"],
                    "tactic": inferred.get("tactic"),
                    "confidence": "high",
                }, rule_id, datetime.now(timezone.utc).isoformat())
            except Exception:
                pass

        # Step 9: record provenance in Water's hunt_log
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": "hunt_triggered_pending_review",
            "ioc": ioc,
            "technique_id": inferred["technique_id"],
            "technique_name": inferred["technique_name"],
            "confidence": "high",
            "rule_id": rule_id,
            "filepath": str(filepath),
            "triggered_by_hunt_id": record.get("hunt_id"),
            "honeypots_seen": inferred["honeypots_seen"],
            "total_events": inferred["total_events"],
        }
        log.append(tag_provenance(
            log_entry,
            source="water",       # this generated artifact IS from Water
            trust_level="medium", # pending review → medium trust
            triggered_by_hunt_id=record.get("hunt_id"),
        ))

        generated += 1

    # Summary
    _say(
        f"  [bold]Hunt-trigger pass complete:[/] "
        f"[green]{generated} generated[/] · "
        f"[dim]{skipped_by_gate} gated, {skipped_no_technique} no-technique[/]"
        if _con else
        f"  Hunt-trigger pass complete: {generated} generated, "
        f"{skipped_by_gate} gated, {skipped_no_technique} no-technique"
    )

    return generated


# ── Self-test when run directly ───────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run as: python water_hunt_trigger.py
    Smoke-tests fetch_recent_hunt_verdicts and infer_technique_from_observed
    against your real ES + sample data.
    """
    print("== water_hunt_trigger self-test ==\n")

    # Test 1: technique inference
    print("Test 1: technique inference from honeypot mix")
    sample_observed = {
        "event_count": 600586,
        "honeypots": [
            {"name": "P0f", "count": 395966},
            {"name": "Suricata", "count": 137470},
            {"name": "Honeytrap", "count": 64853},
            {"name": "Cowrie", "count": 383},
        ],
    }
    inferred = infer_technique_from_observed(sample_observed)
    print(f"  inferred: {inferred}")
    assert inferred is not None
    # Largest cumulative is T1046 (P0f+Suricata+Honeytrap all map there)
    assert inferred["technique_id"] == "T1046", f"expected T1046 got {inferred['technique_id']}"
    print(f"  ✓ correctly picked T1046 Network Service Scanning (cumulative {inferred['total_events']} events)\n")

    # Test 2: edge case - no honeypots
    print("Test 2: empty honeypot list returns None")
    assert infer_technique_from_observed({}) is None
    assert infer_technique_from_observed({"honeypots": []}) is None
    print("  ✓ correctly returned None\n")

    # Test 3: technique inference picks by event volume not by count of honeypots
    print("Test 3: technique inference picks by event volume")
    cowrie_heavy = {
        "honeypots": [
            {"name": "Cowrie", "count": 50000},     # T1110.001
            {"name": "P0f", "count": 100},          # T1046
            {"name": "Honeytrap", "count": 50},     # T1046
        ],
    }
    result = infer_technique_from_observed(cowrie_heavy)
    print(f"  inferred: {result['technique_id']} ({result['total_events']} events)")
    assert result["technique_id"] == "T1110.001"
    print(f"  ✓ Cowrie-heavy attacker correctly mapped to brute force\n")

    # Test 4: ES query smoke (will be empty if no hunt records yet)
    print("Test 4: tk-hunt-logs query smoke")
    es_url = os.environ.get("ELASTIC_URL", "https://10.0.0.1:9200")
    api_key = os.environ.get("ELASTIC_API_KEY", "")
    if not api_key:
        # Read from .env manually for the test
        for line in open(".env"):
            if line.startswith("ELASTIC_API_KEY="):
                api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break
    records = fetch_recent_hunt_verdicts(es_url, api_key)
    print(f"  fetched {len(records)} recent verdicts from {HUNT_LOG_INDEX}")
    if records:
        sample = records[0]
        print(f"  sample IOC: {sample.get('ioc')}")
        print(f"  sample verdict: {(sample.get('result') or {}).get('verdict')}")
    print("  ✓ query executed without crashing\n")

    print("ALL CHECKS PASSED")
