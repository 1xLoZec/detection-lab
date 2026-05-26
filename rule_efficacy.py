#!/usr/bin/env python3
"""
Tall Kitchen — rule efficacy counter.

For every technique Water has deployed a detection rule for, ask Elasticsearch how
many REAL security alerts that rule has produced, and when it first and last fired.
Writes state/rule_efficacy.json. Reports honestly: rules that fired vs rules still dormant.

No invented data. Counts come straight from the live alerts index.
"""
import os, json, sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings()  # self-signed ES cert on the lab box

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

HERE = Path(__file__).resolve().parent
STATE_DIR = HERE / "state"
ALERTS_INDEX = ".internal.alerts-security.alerts-default-*"

ELASTIC_URL     = os.getenv("ELASTIC_URL", "https://10.0.0.1:9200")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")


def _headers():
    h = {"Content-Type": "application/json"}
    if ELASTIC_API_KEY:
        h["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"
    return h


def fires_for_technique(tech_id):
    """Return (count, first_fired, last_fired) for a technique tag like attack.t1218.011."""
    tag = "attack." + tech_id.lower()
    body = {
        "size": 0,
        "query": {"term": {"kibana.alert.rule.tags": tag}},
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last":  {"max": {"field": "@timestamp"}},
        },
    }
    try:
        r = requests.post(f"{ELASTIC_URL}/{ALERTS_INDEX}/_search",
                          headers=_headers(), data=json.dumps(body),
                          verify=False, timeout=15)
    except Exception as e:
        return None, None, None, f"request failed: {type(e).__name__}"
    if r.status_code != 200:
        return None, None, None, f"HTTP {r.status_code}"
    j = r.json()
    count = j.get("hits", {}).get("total", {}).get("value", 0)
    aggs = j.get("aggregations", {})
    first = (aggs.get("first") or {}).get("value_as_string")
    last  = (aggs.get("last")  or {}).get("value_as_string")
    return count, first, last, None


def main():
    seen_path = STATE_DIR / "seen_techniques.json"
    if not seen_path.exists():
        print("no seen_techniques.json found"); sys.exit(1)
    seen = json.loads(seen_path.read_text())

    results = {}
    fired, dormant, errors = 0, 0, 0
    for tech_id, meta in seen.items():
        count, first, last, err = fires_for_technique(tech_id)
        if err:
            errors += 1
            results[tech_id] = {"error": err}
            continue
        results[tech_id] = {
            "technique_name": meta.get("technique_name"),
            "tactic":         meta.get("tactic"),
            "rule_id":        meta.get("rule_id"),
            "deployed_at":    meta.get("deployed_at"),
            "fire_count":     count,
            "first_fired":    first,
            "last_fired":     last,
        }
        if count > 0:
            fired += 1
        else:
            dormant += 1

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts_index": ALERTS_INDEX,
        "total_rules":  len(seen),
        "rules_fired":  fired,
        "rules_dormant": dormant,
        "rules_error":  errors,
        "by_technique": results,
    }
    (STATE_DIR / "rule_efficacy.json").write_text(json.dumps(out, indent=2))

    # readable summary
    print(f"\n  Tall Kitchen rule efficacy")
    print(f"  {'-'*46}")
    print(f"  rules deployed : {len(seen)}")
    print(f"  have fired     : {fired}")
    print(f"  still dormant  : {dormant}")
    if errors:
        print(f"  query errors   : {errors}")
    print(f"  {'-'*46}")
    ranked = sorted(
        [(t, r) for t, r in results.items() if "fire_count" in r],
        key=lambda x: x[1]["fire_count"], reverse=True)
    for t, r in ranked:
        if r["fire_count"] > 0:
            print(f"  {t:<12} {r['fire_count']:>6} fires   last: {(r['last_fired'] or '')[:16]}   {r['technique_name']}")
    print(f"\n  dormant (never fired):")
    for t, r in ranked:
        if r["fire_count"] == 0:
            print(f"  {t:<12}      0          {r['technique_name']}")
    print(f"\n  wrote state/rule_efficacy.json\n")


if __name__ == "__main__":
    main()
