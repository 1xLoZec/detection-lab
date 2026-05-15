#!/usr/bin/env python3
"""
1xLoZec Detection Lab
tallkitchen_hunt — Analyst-facing IOC enrichment companion
Loads credentials from .env automatically.

Usage:
    python tallkitchen_hunt.py <ioc>              # hunt an IOC (check memory first)
    python tallkitchen_hunt.py <ioc> --fresh      # skip memory, re-enrich
    python tallkitchen_hunt.py --history          # show recent hunts
    python tallkitchen_hunt.py --history <ioc>    # show past hunts for one IOC

Phase 2 scope: Engine + transmission (memory layer).
Memory layer: SQLite local cache + ES hunt-logs-* canonical record.
Honest about what it doesn't know yet (every other bucket).
"""
import os
import sys
import re
import json
import uuid
import socket
import sqlite3
import argparse
import warnings
import urllib3
from pathlib import Path
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

TPOT_INDEX      = "tpot-*"
HUNT_LOGS_INDEX = "tk-hunt-logs"   # we write to tk-hunt-logs (no glob); ES creates as-needed

# Memory layer — local SQLite cache, lives next to Water's state but in its own dir
MEMORY_DIR  = Path(__file__).parent / "state" / "tallkitchen"
MEMORY_DB   = MEMORY_DIR / "hunt_memory.db"
HUNTER_ID   = socket.gethostname()  # provenance: which machine ran the hunt


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


def elk_index_doc(index: str, doc: dict) -> bool:
    """POST a document to <index>/_doc. Returns True on success, False on failure.
    Failures are non-fatal — Hunt logs the issue but doesn't block on ES being down."""
    headers = {"Content-Type": "application/json"}
    if ELASTIC_API_KEY:
        headers["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"
    try:
        r = requests.post(
            f"{ELASTIC_URL}/{index}/_doc",
            headers=headers,
            json=doc,
            verify=False,
            timeout=10,
        )
        r.raise_for_status()
        return True
    except Exception:
        return False


# ── Memory layer (the transmission) ───────────────────────────────────────────
# Local SQLite cache for fast "have I seen this before?" lookups.
# Every hunt also gets shipped to ES tk-hunt-logs index (canonical record + Water-readable).

MEMORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS hunts (
    hunt_id        TEXT PRIMARY KEY,
    timestamp_utc  TEXT NOT NULL,
    ioc            TEXT NOT NULL,
    ioc_type       TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    notes          TEXT DEFAULT '',
    source         TEXT NOT NULL,       -- provenance: 'user' for direct CLI hunts
    trust_level    TEXT NOT NULL,       -- 'high' | 'medium' | 'low'
    verifier_id    TEXT NOT NULL,       -- machine hostname that ran the hunt
    duration_ms    INTEGER,
    es_synced      INTEGER DEFAULT 0    -- 1 if successfully written to ES, 0 if not
);
CREATE INDEX IF NOT EXISTS idx_hunts_ioc       ON hunts(ioc);
CREATE INDEX IF NOT EXISTS idx_hunts_timestamp ON hunts(timestamp_utc);
"""


def memory_init() -> sqlite3.Connection:
    """Create memory directory and DB if they don't exist, return open connection."""
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB)
    conn.row_factory = sqlite3.Row
    conn.executescript(MEMORY_SCHEMA)
    conn.commit()
    return conn


def memory_lookup_ioc(conn: sqlite3.Connection, ioc: str) -> list:
    """Return all past hunts for this IOC, newest first."""
    rows = conn.execute(
        "SELECT hunt_id, timestamp_utc, result_json, notes "
        "FROM hunts WHERE ioc = ? ORDER BY timestamp_utc DESC",
        (ioc,),
    ).fetchall()
    return [dict(r) for r in rows]


def memory_record_hunt(
    conn: sqlite3.Connection,
    ioc: str,
    ioc_type: str,
    result: dict,
    duration_ms: int,
) -> str:
    """Write a hunt to SQLite and ship a copy to ES. Returns the hunt_id."""
    hunt_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    result_json = json.dumps(result, default=str)

    # 1. Local SQLite write
    conn.execute(
        "INSERT INTO hunts (hunt_id, timestamp_utc, ioc, ioc_type, result_json, "
        "source, trust_level, verifier_id, duration_ms, es_synced) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (hunt_id, timestamp, ioc, ioc_type, result_json,
         "user", "high", HUNTER_ID, duration_ms),
    )
    conn.commit()

    # 2. ES write (canonical record, Water reads from here)
    es_doc = {
        "@timestamp":     timestamp,
        "hunt_id":        hunt_id,
        "ioc":            ioc,
        "ioc_type":       ioc_type,
        "result":         result,
        "source":         "user",
        "trust_level":    "high",
        "verifier_id":    HUNTER_ID,
        "duration_ms":    duration_ms,
        "buckets_populated": [k for k, v in result.items() if v],
    }
    if elk_index_doc(HUNT_LOGS_INDEX, es_doc):
        conn.execute("UPDATE hunts SET es_synced = 1 WHERE hunt_id = ?", (hunt_id,))
        conn.commit()

    return hunt_id


def memory_recent_hunts(conn: sqlite3.Connection, limit: int = 50) -> list:
    """Return the most recent N hunts across all IOCs."""
    rows = conn.execute(
        "SELECT hunt_id, timestamp_utc, ioc, ioc_type, notes "
        "FROM hunts ORDER BY timestamp_utc DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


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
        "honeypots": [{"name": b["key"], "count": b["doc_count"]} for b in honeypot_buckets],
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
        breakdown = ", ".join(f"{h['name']} ({h['count']})" for h in observed["honeypots"])
        table.add_row("Honeypots", breakdown)
    if observed.get("first_seen"):
        table.add_row("First seen", observed["first_seen"])
    if observed.get("last_seen"):
        table.add_row("Last seen",  observed["last_seen"])
    console.print(table)
    console.print()


def render_memory(past_hunts: list) -> None:
    """
    Show what Hunt has seen for this IOC before. Only renders when there's history.
    """
    if not past_hunts:
        return

    n = len(past_hunts)
    most_recent = past_hunts[0]
    ts = most_recent["timestamp_utc"]
    # Friendly elapsed-time string
    try:
        seen = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - seen
        if delta.total_seconds() < 60:
            elapsed = f"{int(delta.total_seconds())}s ago"
        elif delta.total_seconds() < 3600:
            elapsed = f"{int(delta.total_seconds() / 60)}m ago"
        elif delta.total_seconds() < 86400:
            elapsed = f"{int(delta.total_seconds() / 3600)}h ago"
        else:
            elapsed = f"{delta.days}d ago"
    except Exception:
        elapsed = "previously"

    console.print("[bold yellow]MEMORY[/] [dim](Hunt has seen this before)[/]")
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Last hunted", f"{elapsed}  [dim]({ts})[/]")
    table.add_row("Total hunts", str(n))
    if most_recent.get("notes"):
        table.add_row("Last note",  most_recent["notes"])
    console.print(table)
    console.print("[dim]  Tip: re-run with --fresh to re-enrich and ignore memory.[/]")
    console.print()


def render_honest_limits(ioc_type: str) -> None:
    """
    Hunt is honest about what it can't do yet.
    Every bucket not implemented becomes a LIMIT line.
    """
    console.print("[bold yellow]LIMITS[/] [dim](what Hunt doesn't know yet)[/]")
    msgs = [
        "VERDICT not computed — reputation logic not yet implemented",
        "ATT&CK mapping not yet implemented",
        "External enrichment (AbuseIPDB / VirusTotal / URLhaus) not yet wired up",
        "Pattern detection on unknowns not yet implemented",
        "Pivot suggestions not yet implemented",
    ]
    for m in msgs:
        console.print(f"  [dim]·[/] {m}")
    console.print()


def render_history_list(hunts: list, header: str = "RECENT HUNTS") -> None:
    """Render a list of past hunts (used by --history command)."""
    console.print(f"[bold cyan]{header}[/]")
    if not hunts:
        console.print("  [dim]No hunts recorded yet.[/]")
        console.print()
        return
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("When")
    table.add_column("IOC")
    table.add_column("Type")
    table.add_column("Notes", overflow="fold")
    for h in hunts:
        ts = h["timestamp_utc"]
        try:
            seen = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            delta = datetime.now(timezone.utc) - seen
            if delta.total_seconds() < 3600:
                when = f"{int(delta.total_seconds() / 60)}m ago"
            elif delta.total_seconds() < 86400:
                when = f"{int(delta.total_seconds() / 3600)}h ago"
            else:
                when = f"{delta.days}d ago"
        except Exception:
            when = ts[:19]
        table.add_row(when, h["ioc"], h["ioc_type"], h.get("notes") or "")
    console.print(table)
    console.print()


# ── Main ──────────────────────────────────────────────────────────────────────
def hunt(ioc: str, fresh: bool = False) -> int:
    """Run a hunt against an IOC. Returns exit code."""
    ioc_type = detect_ioc_type(ioc)
    render_header(ioc, ioc_type)

    if ioc_type != "ipv4":
        console.print(f"[bold red]Hunt currently only supports IPv4 addresses.[/]")
        console.print(f"[dim]Detected type: {ioc_type}. Support for hashes and domains is next.[/]")
        console.print()
        return 2

    conn = memory_init()

    # MEMORY check first — the "have I seen this before?" gate
    past_hunts = memory_lookup_ioc(conn, ioc)
    if past_hunts and not fresh:
        render_memory(past_hunts)

    # Run fresh enrichment (always, for now — Phase 3 may add "show cached" mode)
    started = datetime.now(timezone.utc)
    identity = bucket_identity_ip(ioc)
    if identity.get("error"):
        console.print(f"[bold red]ELK query failed:[/] {identity['error']}")
        conn.close()
        return 1
    observed = bucket_observed_ip(ioc)
    duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

    render_identity(identity)
    render_observed(observed)
    render_honest_limits(ioc_type)

    # Record this hunt to memory (SQLite + ES)
    result = {"identity": identity, "observed": observed}
    hunt_id = memory_record_hunt(conn, ioc, ioc_type, result, duration_ms)
    console.print(f"[dim]hunt_id: {hunt_id}  ·  {duration_ms}ms[/]")
    console.print()

    conn.close()
    return 0


def show_history(ioc: str = None, limit: int = 50) -> int:
    """Show past hunts. Either filtered by IOC or recent across all IOCs."""
    conn = memory_init()
    console.print()
    console.print(f"[bold cyan]🥄 tallkitchen hunt[/]  ·  [dim]history[/]")
    console.print()

    if ioc:
        hunts = memory_lookup_ioc(conn, ioc)
        render_history_list(hunts, header=f"HUNTS FOR {ioc}")
    else:
        hunts = memory_recent_hunts(conn, limit=limit)
        render_history_list(hunts, header=f"LAST {limit} HUNTS")

    conn.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tallkitchen_hunt",
        description="Tall Kitchen Hunt — analyst IOC enrichment companion.",
    )
    parser.add_argument("ioc", nargs="?",
                        help="The IOC to investigate (IPv4 only currently)")
    parser.add_argument("--fresh", action="store_true",
                        help="Skip memory check, re-enrich from scratch")
    parser.add_argument("--history", action="store_true",
                        help="Show recent hunts (or pass an IOC to filter)")
    args = parser.parse_args()

    try:
        if args.history:
            return show_history(ioc=args.ioc.strip() if args.ioc else None)
        if not args.ioc:
            parser.error("ioc is required unless --history is given")
        return hunt(args.ioc.strip(), fresh=args.fresh)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
