#!/usr/bin/env python3
"""
1xLoZec Detection Lab
tallkitchen_hunt — Analyst-facing IOC enrichment companion
Loads credentials from .env automatically.

Usage:
    python tallkitchen_hunt.py <ioc>

Day-one scope: IPs only. IDENTITY + OBSERVED buckets against tpot-* index.
Honest about what it doesn't know yet (every other bucket).
"""
import os
import sys
import re
import argparse
import warnings
import urllib3
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.text import Text

# ── Setup ─────────────────────────────────────────────────────────────────────
load_dotenv()
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# ── Config ────────────────────────────────────────────────────────────────────
ELASTIC_URL     = os.getenv("ELASTIC_URL",     "https://10.0.0.1:9200")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

TPOT_INDEX = "tpot-*"

# ── Console ───────────────────────────────────────────────────────────────────
console = Console()

# ── IOC type detection ────────────────────────────────────────────────────────
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,}$"
)


def detect_ioc_type(ioc: str) -> str:
    """Return 'ipv4', 'sha256', 'md5', 'sha1', 'domain', or 'unknown'."""
    if IPV4_RE.match(ioc):
        return "ipv4"
    if SHA256_RE.match(ioc):
        return "sha256"
    if SHA1_RE.match(ioc):
        return "sha1"
    if MD5_RE.match(ioc):
        return "md5"
    if DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


# ── ELK query helper ──────────────────────────────────────────────────────────
def elk_search(index: str, query: dict) -> dict:
    """POST to ELK _search, return parsed JSON. Mirrors Water's pattern."""
    headers = {"Content-Type": "application/json"}
    if ELASTIC_API_KEY:
        headers["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"
    r = requests.post(
        f"{ELASTIC_URL}/{index}/_search",
        headers=headers,
        json=query,
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


# ── IDENTITY bucket ───────────────────────────────────────────────────────────
def bucket_identity_ip(ip: str) -> dict:
    """
    For an IP, return what we can derive without external APIs.
    Day-one: just the IP itself + any GeoIP/ASN data T-Pot's Logstash already enriched.
    T-Pot stores attacker IP in `src_ip` and enriches into `geoip` / `geoip_ext`.
    Prefer `geoip` (per-event) but fall back to `geoip_ext` if `geoip` is empty.
    """
    query = {
        "size": 1,
        "_source": ["src_ip", "geoip", "geoip_ext"],
        "query": {"term": {"src_ip": ip}},
    }
    try:
        result = elk_search(TPOT_INDEX, query)
    except Exception as e:
        return {"ip": ip, "error": str(e)}

    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return {"ip": ip}  # Nothing in T-Pot, identity is just the IP

    src = hits[0].get("_source", {}) or {}
    geo = src.get("geoip") or {}
    # geoip is sometimes {} (geoip_lookup_failure). Fall back to geoip_ext.
    if not geo:
        geo = src.get("geoip_ext") or {}

    return {
        "ip": ip,
        "country": geo.get("country_name") or geo.get("country_code2"),
        "city": geo.get("city_name"),
        "asn": geo.get("asn"),
        "asn_org": geo.get("as_org"),
    }


# ── OBSERVED bucket ───────────────────────────────────────────────────────────
def bucket_observed_ip(ip: str) -> dict:
    """
    For an IP, query T-Pot for event count, honeypot breakdown, first/last seen.
    T-Pot uses `src_ip` as the attacker IP and `type` (a keyword field) for the honeypot name.
    """
    query = {
        "size": 0,
        "track_total_hits": True,  # ES caps total.value at 10,000 by default; ask for exact count
        "query": {"term": {"src_ip": ip}},
        "aggs": {
            "honeypots": {
                "terms": {"field": "type.keyword", "size": 20}
            },
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen":  {"max": {"field": "@timestamp"}},
        },
    }
    try:
        result = elk_search(TPOT_INDEX, query)
    except Exception as e:
        return {"error": str(e)}

    total = result.get("hits", {}).get("total", {})
    if isinstance(total, dict):
        total = total.get("value", 0)

    aggs = result.get("aggregations", {}) or {}
    honeypot_buckets = (aggs.get("honeypots") or {}).get("buckets", []) or []
    first_seen = (aggs.get("first_seen") or {}).get("value_as_string")
    last_seen  = (aggs.get("last_seen")  or {}).get("value_as_string")

    return {
        "event_count": total,
        "honeypots": [(b["key"], b["doc_count"]) for b in honeypot_buckets],
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


# ── Rendering ─────────────────────────────────────────────────────────────────
def render_header(ioc: str, ioc_type: str) -> None:
    console.print()
    console.print(f"[bold cyan]🥄 tallkitchen hunt[/]  ·  [dim]1xLoZec Detection Lab[/]")
    console.print(f"[bold]> {ioc}[/]  [dim]({ioc_type})[/]")
    console.print()


def render_identity(identity: dict) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("IP",         identity.get("ip") or "—")
    table.add_row("ASN",        str(identity.get("asn") or "—"))
    table.add_row("ASN Org",    identity.get("asn_org") or "—")
    table.add_row("Country",    identity.get("country") or "—")
    table.add_row("City",       identity.get("city") or "—")
    console.print("[bold yellow]IDENTITY[/]")
    console.print(table)
    console.print()


def render_observed(observed: dict) -> None:
    if observed.get("error"):
        console.print("[bold yellow]OBSERVED[/]")
        console.print(f"  [red]Error querying T-Pot:[/] {observed['error']}")
        console.print()
        return

    count = observed.get("event_count", 0)
    console.print("[bold yellow]OBSERVED[/] [dim](T-Pot)[/]")
    if count == 0:
        console.print("  [dim]No events. This IP has not been seen by your honeypots.[/]")
        console.print()
        return

    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Events", str(count))
    if observed.get("honeypots"):
        breakdown = ", ".join(f"{name} ({c})" for name, c in observed["honeypots"])
        table.add_row("Honeypots", breakdown)
    if observed.get("first_seen"):
        table.add_row("First seen", observed["first_seen"])
    if observed.get("last_seen"):
        table.add_row("Last seen",  observed["last_seen"])
    console.print(table)
    console.print()


def render_honest_limits(ioc_type: str) -> None:
    """
    Day-one Hunt is honest about what it can't do yet.
    Every bucket not implemented becomes a LIMIT line.
    """
    console.print("[bold yellow]LIMITS[/] [dim](what Hunt doesn't know yet)[/]")
    msgs = [
        "VERDICT not computed — reputation logic not yet implemented",
        "ATT&CK mapping not yet implemented",
        "External enrichment (AbuseIPDB / VirusTotal / URLhaus) not yet wired up",
        "Pattern detection on unknowns not yet implemented",
        "Hunt history logging to ELK not yet implemented",
    ]
    for m in msgs:
        console.print(f"  [dim]·[/] {m}")
    console.print()


# ── Main ──────────────────────────────────────────────────────────────────────
def hunt(ioc: str) -> int:
    ioc_type = detect_ioc_type(ioc)
    render_header(ioc, ioc_type)

    if ioc_type != "ipv4":
        console.print(f"[bold red]Day-one Hunt only supports IPv4 addresses.[/]")
        console.print(f"[dim]Detected type: {ioc_type}. Support for hashes and domains is next.[/]")
        console.print()
        return 2

    identity = bucket_identity_ip(ioc)
    if identity.get("error"):
        console.print(f"[bold red]ELK query failed:[/] {identity['error']}")
        return 1

    observed = bucket_observed_ip(ioc)

    render_identity(identity)
    render_observed(observed)
    render_honest_limits(ioc_type)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tallkitchen_hunt",
        description="Tall Kitchen Hunt — analyst IOC enrichment companion (day-one).",
    )
    parser.add_argument("ioc", help="The IOC to investigate (IPv4 only in day-one)")
    args = parser.parse_args()

    try:
        return hunt(args.ioc.strip())
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
