#!/usr/bin/env python3
"""
hunt_water_rules.py — Hunt-side reader for Water's Sigma detection rules

Phase 6.C integration: gives Hunt visibility into what Water rules cover the
current attacker's likely ATT&CK techniques. Renders as a new RULES bucket
between EXTERNAL and PIVOTS.

CRITICAL DIFFERENCES vs the Water-side bridge:
  - Hunt is READ-ONLY here. Never modifies, deletes, or executes Water rules.
  - No safety gating needed (no closed-loop risk — Hunt just displays metadata).
  - No LLM involvement (no hallucination risk — just YAML parsing).
  - Hunt-triggered rules in pending_review state are surfaced with their status
    so the analyst can see them too (transparency: "Water already generated
    this from your last hunt, awaiting your review").

The technique inference reuses water_hunt_trigger's HONEYPOT_TO_TECHNIQUE map
so both pillars use the same honeypot→ATT&CK semantics — no drift possible.
"""

import re
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# Where Water writes rules
SIGMA_DIR             = Path("detections/sigma")
SIGMA_HUNT_DIR        = Path("detections/sigma/hunt-triggered")


def _infer_techniques_from_observed(observed: dict) -> list:
    """
    Return a list of ATT&CK technique IDs that this attacker's honeypot mix
    suggests. Uses water_hunt_trigger's mapping so both pillars stay aligned.
    Returns top 3 techniques by cumulative event volume, with the dominant
    one first. May be empty for IOCs with no honeypot activity (e.g. DROP-only).
    """
    try:
        from water_hunt_trigger import HONEYPOT_TO_TECHNIQUE
    except ImportError:
        return []

    honeypots = observed.get("honeypots", []) or []
    if not honeypots:
        return []

    technique_totals = {}
    for hp in honeypots:
        name = hp.get("name") or ""
        count = hp.get("count", 0) or 0
        mapping = HONEYPOT_TO_TECHNIQUE.get(name)
        if not mapping:
            continue
        tid = mapping["id"]
        if tid not in technique_totals:
            technique_totals[tid] = {"id": tid, "name": mapping["name"], "events": 0}
        technique_totals[tid]["events"] += count

    sorted_techniques = sorted(
        technique_totals.values(),
        key=lambda t: t["events"],
        reverse=True,
    )
    return [t["id"] for t in sorted_techniques[:3]]


def _parse_rule_file(path: Path) -> dict:
    """
    Parse a Sigma YAML file. Returns minimal dict with the fields Hunt needs.
    Handles the provenance comment block at the top of hunt-triggered rules.
    Returns None if file is unparseable or missing required fields.

    We don't need full Sigma semantics — just enough to display rule cards
    (title, technique tags, status, IOC if hunt-triggered).
    """
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        return None

    # Strip any leading comment-block (hunt-triggered rules have a # provenance header)
    yaml_lines = []
    triggered_by_hunt_id = None
    triggered_by_ioc = None
    in_yaml = False
    for line in text.splitlines():
        # Comment-block parsing — extract provenance hints before YAML starts
        if not in_yaml:
            if line.startswith("# Triggered by hunt_id:"):
                triggered_by_hunt_id = line.split(":", 1)[1].strip()
                continue
            if line.startswith("# IOC:"):
                triggered_by_ioc = line.split(":", 1)[1].strip()
                continue
            if line.startswith("#") or line.strip() == "":
                continue
            # First non-comment non-blank line — YAML starts here
            in_yaml = True
        yaml_lines.append(line)

    yaml_text = "\n".join(yaml_lines)
    if not yaml_text.strip():
        return None

    # Try full YAML parse if available; otherwise regex-extract the fields we need
    parsed = None
    if YAML_AVAILABLE:
        try:
            parsed = yaml.safe_load(yaml_text)
            if not isinstance(parsed, dict):
                parsed = None
        except yaml.YAMLError:
            parsed = None

    if parsed is None:
        # Fallback regex parser — extracts top-level fields needed for display
        parsed = {}
        for field in ("title", "id", "status", "level", "description"):
            m = re.search(rf"^{field}:\s*(.+)$", yaml_text, re.MULTILINE)
            if m:
                parsed[field] = m.group(1).strip().strip("'\"")
        # tags — multi-line list
        tags = []
        in_tags = False
        for line in yaml_lines:
            stripped = line.rstrip()
            if stripped == "tags:" or stripped.startswith("tags:"):
                in_tags = True
                continue
            if in_tags:
                if stripped.startswith("  - ") or stripped.startswith("    - "):
                    tags.append(stripped.lstrip("- ").strip())
                elif stripped and not stripped.startswith(" "):
                    break
        if tags:
            parsed["tags"] = tags

    title = parsed.get("title", path.stem)
    tags = parsed.get("tags") or []
    technique_ids = sorted({
        t.split(".")[1].upper().replace("T", "T")
        for t in tags
        if isinstance(t, str) and t.lower().startswith("attack.t")
    })
    # Normalize back to T-format (e.g. "T1046", "T1110.001")
    techniques = []
    for raw in tags:
        if not isinstance(raw, str):
            continue
        if raw.lower().startswith("attack.t"):
            # "attack.t1046" → "T1046"
            tid_lower = raw.split(".", 1)[1]
            if tid_lower.startswith("t"):
                techniques.append("T" + tid_lower[1:])
            else:
                techniques.append(tid_lower.upper())

    return {
        "path":                  str(path),
        "filename":              path.name,
        "title":                 title,
        "id":                    parsed.get("id"),
        "status":                parsed.get("status", "?"),
        "level":                 parsed.get("level", "?"),
        "techniques":            techniques,
        "is_hunt_triggered":     "hunt-triggered" in str(path),
        "triggered_by_hunt_id":  triggered_by_hunt_id,
        "triggered_by_ioc":      triggered_by_ioc,
    }


def find_rules_for_techniques(technique_ids: list) -> list:
    """
    Walk the detections/sigma/ tree (production + hunt-triggered) and return
    rules tagged with any of the given technique IDs.

    Matches are case-insensitive on the technique ID. Sub-techniques (T1110.001)
    match both the parent (T1110) and the exact sub-technique.
    """
    if not technique_ids:
        return []
    # Build the set of technique IDs we'll match (exact + parents of sub-techniques)
    targets = set()
    for tid in technique_ids:
        tid_upper = tid.upper()
        targets.add(tid_upper)
        if "." in tid_upper:
            targets.add(tid_upper.split(".")[0])

    matches = []

    # Production rules
    if SIGMA_DIR.exists():
        for yml_path in SIGMA_DIR.glob("*.yml"):
            rule = _parse_rule_file(yml_path)
            if not rule:
                continue
            rule_techs = set(t.upper() for t in rule.get("techniques", []))
            # Match if any rule technique is in targets, OR any rule technique's parent is
            if rule_techs & targets:
                matches.append(rule)
                continue
            for rt in rule_techs:
                if "." in rt and rt.split(".")[0] in targets:
                    matches.append(rule)
                    break

    # Hunt-triggered rules (pending_review)
    if SIGMA_HUNT_DIR.exists():
        for yml_path in SIGMA_HUNT_DIR.glob("*.yml"):
            rule = _parse_rule_file(yml_path)
            if not rule:
                continue
            rule_techs = set(t.upper() for t in rule.get("techniques", []))
            if rule_techs & targets:
                matches.append(rule)
                continue
            for rt in rule_techs:
                if "." in rt and rt.split(".")[0] in targets:
                    matches.append(rule)
                    break

    return matches


def bucket_rules(observed: dict, current_ioc: str = None) -> dict:
    """
    Main entry point — Hunt calls this and gets a dict to render.

    Returns:
      {
        "inferred_techniques": [...],
        "matching_rules":      [{rule dict}, ...],
        "self_triggered_rules": [...]   # rules specifically triggered by hunts of THIS IOC
      }
    """
    techniques = _infer_techniques_from_observed(observed)
    matches = find_rules_for_techniques(techniques)

    # Surface separately if any matching rule was triggered by a previous hunt of this exact IOC
    self_triggered = []
    if current_ioc:
        for rule in matches:
            if rule.get("triggered_by_ioc") == current_ioc:
                self_triggered.append(rule)

    return {
        "inferred_techniques":  techniques,
        "matching_rules":       matches,
        "self_triggered_rules": self_triggered,
    }


# ── Self-test when run directly ───────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run as: python hunt_water_rules.py
    Smoke-tests technique inference and rule scanning against real disk state.
    """
    print("== hunt_water_rules self-test ==\n")

    print("Test 1: technique inference from 77.83.240.70 honeypot mix")
    sample_observed = {
        "honeypots": [
            {"name": "P0f", "count": 395966},
            {"name": "Suricata", "count": 137470},
            {"name": "Honeytrap", "count": 64853},
            {"name": "Cowrie", "count": 383},
        ],
    }
    techniques = _infer_techniques_from_observed(sample_observed)
    print(f"  inferred techniques: {techniques}")
    assert "T1046" in techniques, f"expected T1046 in {techniques}"
    print("  ✓ T1046 (Network Service Scanning) correctly inferred\n")

    print("Test 2: rule scanning")
    result = bucket_rules(sample_observed, current_ioc="77.83.240.70")
    print(f"  inferred_techniques:    {result['inferred_techniques']}")
    print(f"  matching_rules:         {len(result['matching_rules'])} rules")
    print(f"  self_triggered_rules:   {len(result['self_triggered_rules'])} rules")
    for rule in result["matching_rules"][:5]:
        print(f"    · {rule['title'][:60]:<60} [{rule['status']}] {rule['techniques']}")
        if rule.get("is_hunt_triggered"):
            print(f"        (hunt-triggered by {rule.get('triggered_by_ioc', '?')})")
    print()

    print("Test 3: empty observed returns empty result")
    empty = bucket_rules({}, "anything")
    assert empty["inferred_techniques"] == []
    assert empty["matching_rules"] == []
    assert empty["self_triggered_rules"] == []
    print("  ✓ empty input handled cleanly\n")

    print("ALL CHECKS PASSED")
