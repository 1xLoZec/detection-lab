#!/usr/bin/env python3
"""
generate_heatmap.py — Auto-generate MITRE ATT&CK Navigator layer from seen_techniques.json

Run: python3 generate_heatmap.py
Output: docs/coverage_layer.json

Load in ATT&CK Navigator:
  https://mitre-attack.github.io/attack-navigator/
  → Open Existing Layer → Upload File → docs/coverage_layer.json
"""

import json
from pathlib import Path
from datetime import datetime, timezone

STATE_FILE  = Path("state/seen_techniques.json")
OUTPUT_FILE = Path("docs/coverage_layer.json")

def generate_layer():
    seen = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}

    techniques = []
    for tid, meta in seen.items():
        # Color by confidence: high=green, medium=yellow, low=light blue
        confidence = meta.get("confidence", "medium").lower()
        color = {
            "high":   "#4caf50",   # green
            "medium": "#ff9800",   # orange
            "low":    "#42a5f5",   # blue
        }.get(confidence, "#ff9800")

        comment = (
            f"Deployed: {meta.get('deployed_at','')[:10]} | "
            f"Confidence: {confidence.upper()} | "
            f"Tactic: {meta.get('tactic','').title()}"
        )

        techniques.append({
            "techniqueID": tid,
            "color":       color,
            "comment":     comment,
            "enabled":     True,
            "score":       1,
            "metadata":    [],
        })

    pct = round(len(seen) / 193 * 100) if seen else 0  # ~193 Enterprise techniques

    layer = {
        "name":        f"1xLoZec Detection Lab — {len(seen)} Techniques Covered ({pct}%)",
        "versions": {
            "attack":    "16",
            "navigator": "4.9",
            "layer":     "4.5",
        },
        "domain":      "enterprise-attack",
        "description": (
            f"Auto-generated from tallkitchen_water detection pipeline. "
            f"{len(seen)} techniques covered as of "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}. "
            f"Green = HIGH confidence, Orange = MEDIUM, Blue = LOW."
        ),
        "filters": {
            "platforms": [
                "Windows", "Linux", "macOS",
                "Network", "PRE", "Containers",
                "IaaS", "SaaS", "Office Suite",
                "Identity Provider",
            ]
        },
        "sorting":       0,
        "layout": {
            "layout":          "side",
            "aggregateFunction": "average",
            "showID":          True,
            "showName":        True,
            "showAggregateScores": False,
            "countUnscored":   False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled":  False,
        "techniques":    techniques,
        "gradient": {
            "colors":   ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "HIGH confidence",   "color": "#4caf50"},
            {"label": "MEDIUM confidence", "color": "#ff9800"},
            {"label": "LOW confidence",    "color": "#42a5f5"},
        ],
        "metadata": [],
        "links":    [],
        "showTacticRowBackground": True,
        "tacticRowBackground":     "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques":       False,
    }

    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(layer, indent=2))
    print(f"Coverage layer written to {OUTPUT_FILE}")
    print(f"  Techniques: {len(seen)}")
    print(f"  Coverage:   ~{pct}%")
    print(f"  Load at:    https://mitre-attack.github.io/attack-navigator/")

if __name__ == "__main__":
    generate_layer()
