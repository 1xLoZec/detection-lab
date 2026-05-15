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

Phase 5 scope: Engine + transmission (memory) + external + VERDICT + PIVOTS.
Memory layer: SQLite local cache + ES hunt-logs-* canonical record.
External (IPv4 only currently):
  - Per-IP API sources: AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox,
    Shodan InternetDB. Each fails gracefully if its API key is missing.
  - List-based source: Spamhaus DROP (no key, daily download + local CIDR check).
Verdict: deterministic weighted scoring across all 7 sources, Mandiant-aligned
  thresholds (benign<40, unknown 40-60, suspicious 60-80, malicious 80+),
  with override rules for IN-DROP and high-volume T-Pot events, plus
  cross-source disagreement detection (Layer 8 hallucination defense).
Pivots: suggested next-step queries — same ASN, same country/recent, same
  honeypot toolkit profile, same DROP range. Each pivot is an informational
  suggestion (count + top examples + Kibana KQL hint), not a command.
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
import ipaddress
import urllib3
from pathlib import Path
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.text import Text
from hunt_water_rules import bucket_rules

# ── Setup ─────────────────────────────────────────────────────────────────────
load_dotenv()
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# ── Config ────────────────────────────────────────────────────────────────────
ELASTIC_URL     = os.getenv("ELASTIC_URL",     "https://10.0.0.1:9200")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

# External source API keys (each optional — Hunt degrades gracefully if missing)
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GREYNOISE_API_KEY  = os.getenv("GREYNOISE_API_KEY",  "")
OTX_API_KEY        = os.getenv("OTX_API_KEY",        "")
ABUSECH_AUTH_KEY   = os.getenv("ABUSECH_AUTH_KEY",   "")   # unlocks URLhaus, MalwareBazaar, ThreatFox, SSLBL

# Self-IPs — IPs that belong to your own infrastructure (droplet, WireGuard mesh,
# home network). Hunt filters these out of pivot results to reduce noise.
# Comma-separated list in env: TALLKITCHEN_SELF_IPS="68.183.139.30,10.0.0.1,..."
SELF_IPS = set(
    ip.strip() for ip in os.getenv("TALLKITCHEN_SELF_IPS", "").split(",")
    if ip.strip()
)

TPOT_INDEX      = "tpot-*"
HUNT_LOGS_INDEX = "tk-hunt-logs"   # we write to tk-hunt-logs (no glob); ES creates as-needed

# Memory layer — local SQLite cache, lives next to Water's state but in its own dir
MEMORY_DIR  = Path(__file__).parent / "state" / "tallkitchen"
MEMORY_DB   = MEMORY_DIR / "hunt_memory.db"
HUNTER_ID   = socket.gethostname()  # provenance: which machine ran the hunt

# Cache TTLs per source (in seconds). Different sources need different freshness.
CACHE_TTL_SECONDS = {
    "abuseipdb":     24 * 3600,   # 24h — abuse scores update slowly
    "virustotal":    24 * 3600,   # 24h
    "greynoise":      6 * 3600,   #  6h — classification can change as new data arrives
    "otx":           24 * 3600,   # 24h
    "threatfox":     12 * 3600,   # 12h — community DB updates frequently
    "internetdb":    24 * 3600,   # 24h — Shodan data is daily-ish
    "spamhaus_drop": 24 * 3600,   # 24h — list itself only changes once per day
}


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

CREATE TABLE IF NOT EXISTS enrichment_cache (
    ioc            TEXT NOT NULL,
    source_name    TEXT NOT NULL,       -- 'abuseipdb', 'virustotal', etc.
    timestamp_utc  TEXT NOT NULL,
    response_json  TEXT NOT NULL,       -- raw parsed response from the source
    status_code    INTEGER,             -- HTTP status; null for non-HTTP sources
    PRIMARY KEY (ioc, source_name)
);
CREATE INDEX IF NOT EXISTS idx_cache_timestamp ON enrichment_cache(timestamp_utc);
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


# ── Enrichment cache ──────────────────────────────────────────────────────────
def cache_get(conn: sqlite3.Connection, ioc: str, source_name: str) -> dict:
    """Return cached enrichment if present and within TTL. Returns None if miss/stale."""
    ttl = CACHE_TTL_SECONDS.get(source_name, 24 * 3600)
    row = conn.execute(
        "SELECT timestamp_utc, response_json FROM enrichment_cache "
        "WHERE ioc = ? AND source_name = ?",
        (ioc, source_name),
    ).fetchone()
    if not row:
        return None
    try:
        cached_at = datetime.fromisoformat(row["timestamp_utc"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - cached_at).total_seconds()
        if age > ttl:
            return None
        return json.loads(row["response_json"])
    except Exception:
        return None


def cache_put(conn: sqlite3.Connection, ioc: str, source_name: str,
              response: dict, status_code: int = None) -> None:
    """Store enrichment response in cache. Overwrites prior entry for same (ioc, source)."""
    conn.execute(
        "INSERT OR REPLACE INTO enrichment_cache "
        "(ioc, source_name, timestamp_utc, response_json, status_code) "
        "VALUES (?, ?, ?, ?, ?)",
        (ioc, source_name, datetime.now(timezone.utc).isoformat(),
         json.dumps(response, default=str), status_code),
    )
    conn.commit()


# ── External source: AbuseIPDB ────────────────────────────────────────────────
# Free tier: 1000 checks/day. Docs: https://docs.abuseipdb.com/
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def abuseipdb_check_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """
    Query AbuseIPDB for an IP. Returns a normalized dict:
        {
          "available": bool,        # True if we got data; False if no key or API down
          "abuse_score": int,       # 0-100
          "total_reports": int,
          "last_reported_at": str,  # ISO timestamp, may be None
          "country_code": str,
          "isp": str,
          "domain": str,
          "is_whitelisted": bool,
          "usage_type": str,
          "_cached": bool,          # True if served from cache
          "_status_code": int,      # HTTP status; useful for debugging
        }
    Empty/skipped result has available=False with a 'reason' field.
    """
    if not ABUSEIPDB_API_KEY:
        return {"available": False, "reason": "no API key (ABUSEIPDB_API_KEY not set in .env)"}

    # Cache check first
    cached = cache_get(conn, ip, "abuseipdb")
    if cached is not None:
        cached["_cached"] = True
        return cached

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
    except Exception as e:
        return {"available": False, "reason": f"request failed: {type(e).__name__}"}

    if r.status_code == 429:
        return {"available": False, "reason": "rate limit hit (AbuseIPDB daily quota)",
                "_status_code": 429}
    if r.status_code != 200:
        return {"available": False, "reason": f"HTTP {r.status_code}",
                "_status_code": r.status_code}

    try:
        body = r.json().get("data", {}) or {}
    except Exception:
        return {"available": False, "reason": "malformed JSON response"}

    normalized = {
        "available":        True,
        "abuse_score":      body.get("abuseConfidenceScore", 0),
        "total_reports":    body.get("totalReports", 0),
        "last_reported_at": body.get("lastReportedAt"),
        "country_code":     body.get("countryCode"),
        "isp":              body.get("isp"),
        "domain":           body.get("domain"),
        "is_whitelisted":   body.get("isWhitelisted", False),
        "usage_type":       body.get("usageType"),
        "_cached":          False,
        "_status_code":     200,
    }
    cache_put(conn, ip, "abuseipdb", normalized, status_code=200)
    return normalized


# ── External source: GreyNoise Community ──────────────────────────────────────
# Free tier — classifies IPs as internet background noise vs targeted activity.
# Docs: https://docs.greynoise.io/reference/community-1
GREYNOISE_URL = "https://api.greynoise.io/v3/community/"


def greynoise_check_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """Query GreyNoise Community API. Returns classification + name (tool/actor) + last seen."""
    if not GREYNOISE_API_KEY:
        return {"available": False, "reason": "no API key (GREYNOISE_API_KEY not set)"}

    cached = cache_get(conn, ip, "greynoise")
    if cached is not None:
        cached["_cached"] = True
        return cached

    headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
    try:
        r = requests.get(f"{GREYNOISE_URL}{ip}", headers=headers, timeout=10)
    except Exception as e:
        return {"available": False, "reason": f"request failed: {type(e).__name__}"}

    # 404 from GreyNoise means "not seen" — that's data, not error
    if r.status_code == 404:
        normalized = {
            "available":      True,
            "classification": "unknown",
            "noise":          False,
            "riot":           False,
            "name":           None,
            "last_seen":      None,
            "message":        "IP not observed by GreyNoise sensors",
            "_cached":        False,
            "_status_code":   404,
        }
        cache_put(conn, ip, "greynoise", normalized, status_code=404)
        return normalized
    if r.status_code == 429:
        return {"available": False, "reason": "rate limit hit", "_status_code": 429}
    if r.status_code != 200:
        return {"available": False, "reason": f"HTTP {r.status_code}",
                "_status_code": r.status_code}

    try:
        body = r.json()
    except Exception:
        return {"available": False, "reason": "malformed JSON"}

    normalized = {
        "available":      True,
        "classification": body.get("classification", "unknown"),  # malicious / benign / unknown
        "noise":          body.get("noise", False),
        "riot":           body.get("riot", False),                # RIOT = known legitimate service
        "name":           body.get("name"),                       # e.g., "Censys", "ZGrab", "Mirai Botnet"
        "last_seen":      body.get("last_seen"),
        "message":        body.get("message"),
        "_cached":        False,
        "_status_code":   200,
    }
    cache_put(conn, ip, "greynoise", normalized, status_code=200)
    return normalized


# ── External source: VirusTotal ───────────────────────────────────────────────
# Free tier: 4 req/min, 500/day. v3 API.
# Docs: https://docs.virustotal.com/reference/ip-info
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def virustotal_check_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """Query VirusTotal for an IP. Returns detection ratio + community votes + reputation."""
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "reason": "no API key (VIRUSTOTAL_API_KEY not set)"}

    cached = cache_get(conn, ip, "virustotal")
    if cached is not None:
        cached["_cached"] = True
        return cached

    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}
    try:
        r = requests.get(f"{VT_BASE_URL}/ip_addresses/{ip}", headers=headers, timeout=10)
    except Exception as e:
        return {"available": False, "reason": f"request failed: {type(e).__name__}"}

    if r.status_code == 429:
        return {"available": False, "reason": "rate limit hit (VT 4/min or 500/day)",
                "_status_code": 429}
    if r.status_code == 404:
        normalized = {
            "available": True, "malicious": 0, "suspicious": 0, "harmless": 0,
            "undetected": 0, "total_engines": 0, "reputation": 0, "community_votes": {},
            "message": "IP not in VirusTotal database",
            "_cached": False, "_status_code": 404,
        }
        cache_put(conn, ip, "virustotal", normalized, status_code=404)
        return normalized
    if r.status_code != 200:
        return {"available": False, "reason": f"HTTP {r.status_code}",
                "_status_code": r.status_code}

    try:
        attrs = (r.json().get("data", {}) or {}).get("attributes", {}) or {}
    except Exception:
        return {"available": False, "reason": "malformed JSON"}

    stats = attrs.get("last_analysis_stats", {}) or {}
    normalized = {
        "available":       True,
        "malicious":       stats.get("malicious", 0),
        "suspicious":      stats.get("suspicious", 0),
        "harmless":        stats.get("harmless", 0),
        "undetected":      stats.get("undetected", 0),
        "total_engines":   sum(stats.values()) if stats else 0,
        "reputation":      attrs.get("reputation", 0),
        "community_votes": attrs.get("total_votes", {}) or {},
        "country":         attrs.get("country"),
        "asn":             attrs.get("asn"),
        "as_owner":        attrs.get("as_owner"),
        "_cached":         False,
        "_status_code":    200,
    }
    cache_put(conn, ip, "virustotal", normalized, status_code=200)
    return normalized


# ── External source: AlienVault OTX ───────────────────────────────────────────
# Free. Returns associated "Pulses" (campaigns/threat reports) for an IOC.
# Docs: https://otx.alienvault.com/api
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


def otx_check_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """Query OTX for an IP. Returns pulse count + top pulse names."""
    if not OTX_API_KEY:
        return {"available": False, "reason": "no API key (OTX_API_KEY not set)"}

    cached = cache_get(conn, ip, "otx")
    if cached is not None:
        cached["_cached"] = True
        return cached

    headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
    try:
        r = requests.get(f"{OTX_BASE_URL}/IPv4/{ip}/general",
                         headers=headers, timeout=10)
    except Exception as e:
        return {"available": False, "reason": f"request failed: {type(e).__name__}"}

    if r.status_code != 200:
        return {"available": False, "reason": f"HTTP {r.status_code}",
                "_status_code": r.status_code}

    try:
        body = r.json() or {}
    except Exception:
        return {"available": False, "reason": "malformed JSON"}

    pulse_info = body.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []
    normalized = {
        "available":     True,
        "pulse_count":   pulse_info.get("count", 0),
        "top_pulses":    [p.get("name") for p in pulses[:5] if p.get("name")],
        "related_indicator_types": list((pulse_info.get("related", {}) or {}).keys()),
        "reputation":    body.get("reputation", 0),
        "_cached":       False,
        "_status_code":  200,
    }
    cache_put(conn, ip, "otx", normalized, status_code=200)
    return normalized


# ── External source: ThreatFox (abuse.ch) ─────────────────────────────────────
# Free with abuse.ch Auth-Key. Community DB of malware C2 / payload infrastructure.
# Docs: https://threatfox.abuse.ch/api/
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def threatfox_check_ioc(conn: sqlite3.Connection, ioc: str, ioc_type: str) -> dict:
    """
    Query ThreatFox for any IOC type. Returns matching malware-family associations.
    ThreatFox accepts IPs, domains, URLs, hashes via the same endpoint.
    """
    if not ABUSECH_AUTH_KEY:
        return {"available": False, "reason": "no Auth-Key (ABUSECH_AUTH_KEY not set)"}

    cached = cache_get(conn, ioc, "threatfox")
    if cached is not None:
        cached["_cached"] = True
        return cached

    headers = {"Auth-Key": ABUSECH_AUTH_KEY, "Content-Type": "application/json"}
    payload = {"query": "search_ioc", "search_term": ioc}
    try:
        r = requests.post(THREATFOX_URL, headers=headers, json=payload, timeout=10)
    except Exception as e:
        return {"available": False, "reason": f"request failed: {type(e).__name__}"}

    if r.status_code != 200:
        return {"available": False, "reason": f"HTTP {r.status_code}",
                "_status_code": r.status_code}

    try:
        body = r.json() or {}
    except Exception:
        return {"available": False, "reason": "malformed JSON"}

    # ThreatFox returns query_status="no_result" when IOC isn't in their DB
    if body.get("query_status") == "no_result":
        normalized = {
            "available": True, "match_count": 0, "matches": [],
            "message": "IOC not in ThreatFox database",
            "_cached": False, "_status_code": 200,
        }
        cache_put(conn, ioc, "threatfox", normalized, status_code=200)
        return normalized

    data = body.get("data", []) or []
    matches = [
        {
            "malware":         m.get("malware_printable"),
            "malware_alias":   m.get("malware_alias"),
            "threat_type":     m.get("threat_type"),
            "confidence":      m.get("confidence_level"),
            "first_seen":      m.get("first_seen"),
            "last_seen":       m.get("last_seen"),
            "tags":            m.get("tags") or [],
        }
        for m in data[:10]  # cap at top 10
    ]
    normalized = {
        "available":    True,
        "match_count":  len(data),
        "matches":      matches,
        "_cached":      False,
        "_status_code": 200,
    }
    cache_put(conn, ioc, "threatfox", normalized, status_code=200)
    return normalized


# ── External source: Shodan InternetDB ────────────────────────────────────────
# Free, no API key required. Lightweight subset of Shodan data: ports, hostnames, CPEs.
# Docs: https://internetdb.shodan.io/
INTERNETDB_URL = "https://internetdb.shodan.io"


def internetdb_check_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """Query Shodan InternetDB. No auth needed. Returns open ports + hostnames + CPEs + tags."""
    cached = cache_get(conn, ip, "internetdb")
    if cached is not None:
        cached["_cached"] = True
        return cached

    try:
        r = requests.get(f"{INTERNETDB_URL}/{ip}", timeout=10)
    except Exception as e:
        return {"available": False, "reason": f"request failed: {type(e).__name__}"}

    if r.status_code == 404:
        # 404 means not scanned/no info — that's data, not error
        normalized = {
            "available": True, "ports": [], "hostnames": [], "cpes": [], "tags": [],
            "vulns": [], "message": "IP not in Shodan InternetDB",
            "_cached": False, "_status_code": 404,
        }
        cache_put(conn, ip, "internetdb", normalized, status_code=404)
        return normalized
    if r.status_code != 200:
        return {"available": False, "reason": f"HTTP {r.status_code}",
                "_status_code": r.status_code}

    try:
        body = r.json() or {}
    except Exception:
        return {"available": False, "reason": "malformed JSON"}

    normalized = {
        "available":    True,
        "ports":        body.get("ports", []) or [],
        "hostnames":    body.get("hostnames", []) or [],
        "cpes":         body.get("cpes", []) or [],
        "tags":         body.get("tags", []) or [],
        "vulns":        body.get("vulns", []) or [],
        "_cached":      False,
        "_status_code": 200,
    }
    cache_put(conn, ip, "internetdb", normalized, status_code=200)
    return normalized


# ── External source: Spamhaus DROP ────────────────────────────────────────────
# Free, no API key. List of CIDR ranges Spamhaus says "don't route" — entire
# netblocks operated by professional spam/cybercrime operations. Different
# pattern from other sources: download list once a day, check IP membership
# locally instead of one API call per hunt.
# Docs: https://www.spamhaus.org/drop/
SPAMHAUS_DROP_URL    = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_DROP_CACHE  = MEMORY_DIR / "spamhaus_drop.txt"
SPAMHAUS_DROP_MAX_AGE_SECONDS = 24 * 3600  # Spamhaus asks: don't fetch more than 1x per day

# In-memory parsed copy, populated on first use, refreshed when file is reloaded
_spamhaus_parsed_ranges = None  # list of (ipaddress.IPv4Network, "SBL12345") tuples
_spamhaus_loaded_from = None    # filepath we parsed, for cache-bust detection


def _spamhaus_drop_refresh_if_stale() -> bool:
    """
    Ensure the local DROP cache file is present and fresh.
    Returns True if a usable file exists after this call, False if not.
    """
    try:
        if SPAMHAUS_DROP_CACHE.exists():
            age = (datetime.now(timezone.utc).timestamp()
                   - SPAMHAUS_DROP_CACHE.stat().st_mtime)
            if age < SPAMHAUS_DROP_MAX_AGE_SECONDS:
                return True
        # File is missing or stale — fetch
        r = requests.get(SPAMHAUS_DROP_URL, timeout=15)
        if r.status_code == 200 and r.text:
            SPAMHAUS_DROP_CACHE.parent.mkdir(parents=True, exist_ok=True)
            SPAMHAUS_DROP_CACHE.write_text(r.text)
            return True
    except Exception:
        pass
    # If a stale file exists, use it rather than nothing
    return SPAMHAUS_DROP_CACHE.exists()


def _spamhaus_drop_load() -> list:
    """
    Parse the local DROP file into a list of (IPv4Network, sbl_id) tuples.
    Cached in-process; reparses only if the file path or mtime changes.
    """
    global _spamhaus_parsed_ranges, _spamhaus_loaded_from
    if not SPAMHAUS_DROP_CACHE.exists():
        return []
    file_marker = (str(SPAMHAUS_DROP_CACHE), SPAMHAUS_DROP_CACHE.stat().st_mtime)
    if _spamhaus_loaded_from == file_marker and _spamhaus_parsed_ranges is not None:
        return _spamhaus_parsed_ranges

    parsed = []
    try:
        for line in SPAMHAUS_DROP_CACHE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # Format: "1.10.16.0/20 ; SBL256894"
            parts = line.split(";", 1)
            cidr = parts[0].strip()
            sbl  = parts[1].strip() if len(parts) > 1 else ""
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    parsed.append((net, sbl))
            except Exception:
                continue
    except Exception:
        return []

    _spamhaus_parsed_ranges = parsed
    _spamhaus_loaded_from   = file_marker
    return parsed


def spamhaus_drop_check_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """
    Check whether an IPv4 falls inside any DROP range.
    Uses local file cache + SQLite per-IP result cache.
    """
    # Per-IP cache check first — even though the lookup is local-fast,
    # this keeps the response shape consistent and lets us re-render
    # the (cached) tag in the renderer.
    cached = cache_get(conn, ip, "spamhaus_drop")
    if cached is not None:
        cached["_cached"] = True
        return cached

    if not _spamhaus_drop_refresh_if_stale():
        return {"available": False, "reason": "DROP list not reachable and no local cache"}

    ranges = _spamhaus_drop_load()
    if not ranges:
        return {"available": False, "reason": "DROP list is empty or malformed"}

    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {"available": False, "reason": f"not a parseable IP: {ip}"}

    if not isinstance(addr, ipaddress.IPv4Address):
        # DROP is IPv4 only
        normalized = {
            "available":  True,
            "in_drop":    False,
            "range":      None,
            "sbl":        None,
            "message":    "DROP is IPv4-only; this IP is IPv6",
            "_cached":    False,
        }
        cache_put(conn, ip, "spamhaus_drop", normalized)
        return normalized

    match = None
    for net, sbl in ranges:
        if addr in net:
            match = (net, sbl)
            break

    if match:
        normalized = {
            "available":  True,
            "in_drop":    True,
            "range":      str(match[0]),
            "sbl":        match[1],
            "message":    "IP is in Spamhaus DROP — netblock flagged as do-not-route",
            "_cached":    False,
        }
    else:
        normalized = {
            "available":  True,
            "in_drop":    False,
            "range":      None,
            "sbl":        None,
            "message":    f"Not in any of {len(ranges)} DROP ranges",
            "_cached":    False,
        }
    cache_put(conn, ip, "spamhaus_drop", normalized)
    return normalized


# ── EXTERNAL bucket ───────────────────────────────────────────────────────────
def bucket_external_ip(conn: sqlite3.Connection, ip: str) -> dict:
    """
    Orchestrate all external IP enrichment sources. Returns a dict keyed by source name.
    Adding new sources: just add another call here.
    """
    return {
        "abuseipdb":     abuseipdb_check_ip(conn, ip),
        "greynoise":     greynoise_check_ip(conn, ip),
        "virustotal":    virustotal_check_ip(conn, ip),
        "otx":           otx_check_ip(conn, ip),
        "threatfox":     threatfox_check_ioc(conn, ip, "ipv4"),
        "internetdb":    internetdb_check_ip(conn, ip),
        "spamhaus_drop": spamhaus_drop_check_ip(conn, ip),
    }


# ── VERDICT bucket ────────────────────────────────────────────────────────────
# Deterministic weighted scoring across all sources. Designed to be auditable —
# every score increment is traceable to a specific source's signal strength.
# Weights derived from industry practice (Mandiant, OpenCTI, Spamhaus docs)
# plus FalconFeeds research showing internal observations + expert-curated feeds
# target 99% TPR vs. community feeds at much lower fidelity.

# Source weights, sum = 105. Each source contributes weight × signal_strength (0..1)
# to a raw score. The raw score is normalized to 0-100 for verdict bands.
SOURCE_WEIGHTS = {
    "tpot":          35,   # Your own honeypot ground truth — verified internal observation
    "spamhaus_drop": 18,   # Tier-1 ISP trust, "extremely low false positives" (Spamhaus docs)
    "greynoise":     15,   # Direct mass-scanning observation, manually curated benign list
    "threatfox":     12,   # abuse.ch curated, per-IOC confidence, 6-month expiry
    "virustotal":    12,   # 90+ engine consensus, but slower for IPs vs files
    "abuseipdb":      8,   # Community-driven (gameable), threshold ≥75 per OpenCTI default
    "otx":            5,   # Highest volume / lowest curation — many low-quality pulses
    # InternetDB intentionally not in this map — it's context, not a verdict vote
}
SOURCE_WEIGHTS_TOTAL = sum(SOURCE_WEIGHTS.values())  # 105

# Verdict bands match Mandiant's published thresholds (see blog: alert scoring at machine scale)
VERDICT_BANDS = [
    (80, "malicious",  "BLOCK"),
    (60, "suspicious", "INVESTIGATE"),
    (40, "unknown",    "MONITOR"),
    (0,  "benign",     "IGNORE"),
]


def _signal_tpot(observed: dict) -> float:
    """T-Pot: event_count → signal strength. log scale to avoid overweighting one-offs."""
    import math
    if observed.get("error"):
        return 0.0
    count = observed.get("event_count", 0) or 0
    if count <= 0:
        return 0.0
    # log10(count) / 4 — so 1 event = 0%, 100 = 50%, 10k = 100%, capped at 1.0
    return min(1.0, math.log10(count) / 4.0)


def _signal_spamhaus_drop(src: dict) -> float:
    """Spamhaus DROP: binary. In a flagged netblock or not."""
    if not src or not src.get("available"):
        return 0.0
    return 1.0 if src.get("in_drop") else 0.0


def _signal_greynoise(src: dict) -> float:
    """GreyNoise: malicious → +1, benign → anti-signal (-1), unknown → 0.
    The anti-signal is intentional — RIOT/benign is high-confidence per their curation."""
    if not src or not src.get("available"):
        return 0.0
    cls = (src.get("classification") or "").lower()
    if cls == "malicious":
        return 1.0
    if cls == "benign":
        return -1.0
    return 0.0


def _signal_threatfox(src: dict) -> float:
    """ThreatFox: malware family matches. Even one match is meaningful (curated)."""
    if not src or not src.get("available"):
        return 0.0
    matches = src.get("match_count", 0) or 0
    if matches <= 0:
        return 0.0
    return min(1.0, matches / 5.0)


def _signal_virustotal(src: dict) -> float:
    """VirusTotal: detection ratio. Industry rule: <3% likely FP, >10% real threat."""
    if not src or not src.get("available"):
        return 0.0
    flagged = (src.get("malicious", 0) or 0) + (src.get("suspicious", 0) or 0)
    total = src.get("total_engines", 0) or 0
    if total == 0:
        return 0.0
    ratio = flagged / total
    if ratio < 0.03:
        return 0.0
    if ratio >= 0.10:
        return 1.0
    # Linear ramp 3% → 10%
    return (ratio - 0.03) / (0.10 - 0.03)


def _signal_abuseipdb(src: dict) -> float:
    """AbuseIPDB: score 0-100. OpenCTI defaults to threshold 75 to avoid FPs.
    Scores below 75 get heavily discounted because community-reportable = gameable."""
    if not src or not src.get("available"):
        return 0.0
    score = src.get("abuse_score", 0) or 0
    if src.get("is_whitelisted"):
        return -0.5  # Whitelisted = anti-signal, but weaker than GreyNoise benign
    if score >= 75:
        return score / 100.0
    # Below threshold — discounted by 2x
    return score / 200.0


def _signal_otx(src: dict) -> float:
    """OTX: pulse_count. High volume / variable quality, so 10+ pulses needed for full signal."""
    if not src or not src.get("available"):
        return 0.0
    pulses = src.get("pulse_count", 0) or 0
    if pulses <= 0:
        return 0.0
    return min(1.0, pulses / 10.0)


def _detect_disagreements(external: dict, observed: dict, raw_score: float) -> list:
    """
    Identify cross-source disagreements (Layer 8 defense from hallucination stack).
    Returns a list of human-readable conflict notes for the analyst to weigh.
    """
    conflicts = []

    gn = external.get("greynoise") or {}
    ab = external.get("abuseipdb") or {}
    vt = external.get("virustotal") or {}
    sh = external.get("spamhaus_drop") or {}
    tpot_events = (observed or {}).get("event_count", 0) or 0

    # GreyNoise benign vs. other malicious signals
    if gn.get("available") and gn.get("classification") == "benign":
        if ab.get("available") and (ab.get("abuse_score") or 0) >= 75:
            conflicts.append(f"GreyNoise classifies as benign but AbuseIPDB scores {ab['abuse_score']}/100")
        if vt.get("available"):
            flagged = (vt.get("malicious") or 0) + (vt.get("suspicious") or 0)
            if flagged >= 5:
                conflicts.append(f"GreyNoise classifies as benign but VirusTotal flagged by {flagged} engines")
        if tpot_events > 100:
            conflicts.append(f"GreyNoise classifies as benign but T-Pot has {tpot_events} events from this IP")

    # GreyNoise RIOT (known legit service) vs. honeypot hits
    if gn.get("available") and gn.get("riot") and tpot_events > 0:
        name = gn.get("name") or "known service"
        conflicts.append(f"GreyNoise marks as RIOT ({name}) but honeypot saw {tpot_events} events — possible source IP spoofing or false-RIOT")

    # T-Pot has heavy activity but per-IP sources are silent
    if tpot_events > 1000:
        silent_sources = []
        if ab.get("available") and (ab.get("abuse_score") or 0) < 25:
            silent_sources.append("AbuseIPDB")
        if vt.get("available") and ((vt.get("malicious") or 0) + (vt.get("suspicious") or 0)) == 0:
            silent_sources.append("VirusTotal")
        if len(silent_sources) >= 2:
            conflicts.append(f"T-Pot has {tpot_events} events but {' and '.join(silent_sources)} both show no signal — IP may be new/unknown to external community")

    # In DROP but per-IP sources clean (this isn't actually a conflict — it's the value-add of DROP)
    # so we don't surface it as a conflict; the DROP marker in the renderer already explains.

    # AbuseIPDB whitelist vs. high abuse score (these can co-exist for cloud providers)
    if ab.get("available") and ab.get("is_whitelisted") and (ab.get("abuse_score") or 0) >= 50:
        conflicts.append(f"AbuseIPDB lists as whitelisted but abuse score is {ab['abuse_score']}/100 — likely shared/cloud infrastructure")

    return conflicts


def _band_for_score(score: float) -> tuple:
    """Map a 0-100 score to (verdict, action) per Mandiant-aligned bands."""
    for threshold, verdict, action in VERDICT_BANDS:
        if score >= threshold:
            return (verdict, action)
    return ("benign", "IGNORE")  # Fallback (shouldn't reach — last band is 0)


def bucket_verdict(observed: dict, external: dict) -> dict:
    """
    Compute the verdict bucket — deterministic, auditable, override-aware.
    Returns a dict with the verdict, action, score, breakdown, conflicts, and floor reasons.
    """
    # 1) Compute signal strength per source
    signals = {
        "tpot":          _signal_tpot(observed),
        "spamhaus_drop": _signal_spamhaus_drop(external.get("spamhaus_drop")),
        "greynoise":     _signal_greynoise(external.get("greynoise")),
        "threatfox":     _signal_threatfox(external.get("threatfox")),
        "virustotal":    _signal_virustotal(external.get("virustotal")),
        "abuseipdb":     _signal_abuseipdb(external.get("abuseipdb")),
        "otx":           _signal_otx(external.get("otx")),
    }

    # 2) Weighted contribution per source (may be negative for anti-signals)
    contributions = {
        name: SOURCE_WEIGHTS[name] * sig
        for name, sig in signals.items()
    }

    # 3) Raw weighted score, normalized to 0-100
    raw_total = sum(contributions.values())
    raw_score = max(0.0, min(100.0, (raw_total / SOURCE_WEIGHTS_TOTAL) * 100.0))

    # 4) Apply override rules — these are not "fudging" — they encode operational truth
    #    (Tier-1 ISPs autoblock on DROP; high T-Pot event counts are direct observation)
    floors = []
    floor_score = raw_score

    sh = external.get("spamhaus_drop") or {}
    tpot_events = (observed or {}).get("event_count", 0) or 0

    if sh.get("in_drop"):
        if tpot_events > 10000:
            # Both signals: IP is in DROP AND your honeypot saw it at scale
            floor_score = max(floor_score, 85.0)
            floors.append("IN DROP + T-Pot ≥10k events → floor 85")
        else:
            floor_score = max(floor_score, 65.0)
            floors.append("IN DROP → floor 65 (SUSPICIOUS)")
    elif tpot_events > 10000:
        floor_score = max(floor_score, 75.0)
        floors.append(f"T-Pot {tpot_events} events → floor 75")

    # 5) Disagreement detection (Layer 8 defense)
    conflicts = _detect_disagreements(external, observed, floor_score)

    # 6) RIOT/benign safety brake — if a high-confidence anti-signal exists,
    #    drop one band as a conservative measure (but don't override DROP)
    gn = external.get("greynoise") or {}
    safety_brake_applied = False
    if not sh.get("in_drop"):  # DROP override always wins
        if gn.get("available") and gn.get("riot"):
            if floor_score >= 60:
                floor_score = 59.0  # Drop to "unknown / MONITOR"
                safety_brake_applied = True
                floors.append(f"GreyNoise RIOT ({gn.get('name') or 'known service'}) → cap at unknown")

    verdict, action = _band_for_score(floor_score)

    return {
        "score":               round(floor_score, 1),
        "raw_score":           round(raw_score, 1),
        "verdict":             verdict,
        "action":              action,
        "signals":             {k: round(v, 3) for k, v in signals.items()},
        "contributions":       {k: round(v, 2) for k, v in contributions.items()},
        "floors_applied":      floors,
        "conflicts":           conflicts,
        "safety_brake":        safety_brake_applied,
    }


# ── PIVOTS bucket ─────────────────────────────────────────────────────────────
# Pivots are *informational suggestions*, not commands. Each pivot answers
# "where else should I look?" and gives the analyst a copy-pasteable starting
# point. The analyst stays in the driver's seat — Hunt is the colleague who
# noticed something interesting, not a command runner.
#
# Design rule: a pivot only gets surfaced if it would return USEFUL results.
# A pivot with 0 results or 1 result (just the IOC itself) gets suppressed.

def _pivot_same_asn(ip: str, identity: dict, lookback_days: int = 7) -> dict:
    """Pivot: other IPs from the same ASN seen by your honeypots."""
    asn = identity.get("asn")
    asn_org = identity.get("asn_org")
    if not asn:
        return None

    # Query T-Pot for distinct IPs in the same ASN, last N days
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                    {"bool": {"should": [
                        {"term": {"geoip.asn": asn}},
                        {"term": {"geoip_ext.asn": asn}},
                    ], "minimum_should_match": 1}},
                ],
                "must_not": [{"term": {"src_ip": ip}}],
            }
        },
        "aggs": {
            "distinct_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "top_ips": {
                "terms": {"field": "src_ip.keyword", "size": 5,
                          "order": {"_count": "desc"}}
            },
        },
    }
    try:
        result = elk_search(TPOT_INDEX, query)
    except Exception:
        return None

    aggs = result.get("aggregations", {}) or {}
    distinct = (aggs.get("distinct_ips") or {}).get("value", 0)
    top_buckets = (aggs.get("top_ips") or {}).get("buckets", []) or []

    if distinct < 1:
        return None  # No siblings in T-Pot, suppress this pivot

    return {
        "type":     "same_asn",
        "question": f"Other IPs from ASN {asn} ({asn_org or '?'}) seen by honeypots in last {lookback_days}d",
        "distinct_count": distinct,
        "top_examples":   [{"ip": b["key"], "events": b["doc_count"]} for b in top_buckets],
        "lookback_days":  lookback_days,
        "query_hint":     f'src_ip:* AND (geoip.asn:{asn} OR geoip_ext.asn:{asn}) AND @timestamp:>=now-{lookback_days}d',
    }


def _pivot_same_country_recent(ip: str, identity: dict, lookback_hours: int = 24) -> dict:
    """Pivot: other IPs from the same country in a recent time window."""
    country = identity.get("country")
    if not country or country == "—":
        return None

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}},
                    {"bool": {"should": [
                        {"term": {"geoip.country_name.keyword": country}},
                        {"term": {"geoip_ext.country_name.keyword": country}},
                    ], "minimum_should_match": 1}},
                ],
                "must_not": [{"term": {"src_ip": ip}}],
            }
        },
        "aggs": {
            "distinct_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "top_ips": {
                "terms": {"field": "src_ip.keyword", "size": 5,
                          "order": {"_count": "desc"}}
            },
        },
    }
    try:
        result = elk_search(TPOT_INDEX, query)
    except Exception:
        return None

    aggs = result.get("aggregations", {}) or {}
    distinct = (aggs.get("distinct_ips") or {}).get("value", 0)
    top_buckets = (aggs.get("top_ips") or {}).get("buckets", []) or []

    if distinct < 1:
        return None

    return {
        "type":     "same_country_recent",
        "question": f"Other IPs from {country} hitting honeypots in last {lookback_hours}h",
        "distinct_count": distinct,
        "top_examples":   [{"ip": b["key"], "events": b["doc_count"]} for b in top_buckets],
        "lookback_hours": lookback_hours,
        "query_hint":     f'src_ip:* AND (geoip.country_name:"{country}" OR geoip_ext.country_name:"{country}") AND @timestamp:>=now-{lookback_hours}h',
    }


def _pivot_same_honeypot_mix(ip: str, observed: dict, lookback_days: int = 7) -> dict:
    """Pivot: other IPs that hit the same combination of honeypot types.
    Useful for finding scanners with similar toolkit profiles."""
    honeypots = observed.get("honeypots") or []
    if len(honeypots) < 2:
        return None  # Single-honeypot scanners aren't distinctive enough

    # Take the top 3 honeypots this IP hit — those are the distinctive toolkit profile
    top_honeypot_names = [h["name"] for h in honeypots[:3]]
    if not top_honeypot_names:
        return None

    # Find other IPs that hit AT LEAST 2 of the same top 3 honeypots
    # (Exact-match would be too strict; "fuzzy fingerprint" is more useful.)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                    {"terms": {"type.keyword": top_honeypot_names}},
                ],
                "must_not": [{"term": {"src_ip": ip}}],
            }
        },
        "aggs": {
            "distinct_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "ips_with_multi_honeypots": {
                "terms": {"field": "src_ip.keyword", "size": 5,
                          "min_doc_count": 10,
                          "order": {"_count": "desc"}}
            },
        },
    }
    try:
        result = elk_search(TPOT_INDEX, query)
    except Exception:
        return None

    aggs = result.get("aggregations", {}) or {}
    distinct = (aggs.get("distinct_ips") or {}).get("value", 0)
    top_buckets = (aggs.get("ips_with_multi_honeypots") or {}).get("buckets", []) or []

    if distinct < 1 or not top_buckets:
        return None

    return {
        "type":     "same_honeypot_mix",
        "question": f"Other IPs hitting similar honeypot mix ({', '.join(top_honeypot_names)}) in last {lookback_days}d",
        "distinct_count": distinct,
        "top_examples":   [{"ip": b["key"], "events": b["doc_count"]} for b in top_buckets],
        "honeypot_profile": top_honeypot_names,
        "lookback_days":    lookback_days,
        "query_hint":       f'type:({" OR ".join(top_honeypot_names)}) AND @timestamp:>=now-{lookback_days}d',
    }


def _pivot_same_drop_range(ip: str, external: dict, lookback_days: int = 30) -> dict:
    """Pivot: other IPs from the same Spamhaus DROP range that hit your honeypots.
    Only fires if the current IP is IN DROP. High-value pivot — same criminal
    netblock activity is exactly the kind of follow-up an analyst wants.

    CURRENTLY DISABLED: T-Pot's src_ip field is mapped as 'text', not 'ip'.
    CIDR-range queries require an 'ip'-typed field. Re-enable once we update
    T-Pot's Logstash index template to map src_ip as type=ip. Until then this
    pivot would return either zero results or wrong results, so we suppress it
    rather than show misleading data.
    """
    return None
    # ↓ Original implementation kept for future revival once mapping is fixed ↓
    sh = external.get("spamhaus_drop") or {}
    if not sh.get("available") or not sh.get("in_drop"):
        return None

    drop_range = sh.get("range")
    sbl = sh.get("sbl")
    if not drop_range:
        return None

    # Build a CIDR range query
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                    {"term": {"src_ip": drop_range}},  # ES treats CIDR string as range query
                ],
                "must_not": [{"term": {"src_ip": ip}}],
            }
        },
        "aggs": {
            "distinct_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "top_ips": {
                "terms": {"field": "src_ip.keyword", "size": 5,
                          "order": {"_count": "desc"}}
            },
        },
    }
    try:
        result = elk_search(TPOT_INDEX, query)
    except Exception:
        return None

    aggs = result.get("aggregations", {}) or {}
    distinct = (aggs.get("distinct_ips") or {}).get("value", 0)
    top_buckets = (aggs.get("top_ips") or {}).get("buckets", []) or []

    if distinct < 1:
        return None

    return {
        "type":     "same_drop_range",
        "question": f"Other IPs in DROP range {drop_range} ({sbl}) seen by honeypots in last {lookback_days}d",
        "distinct_count": distinct,
        "top_examples":   [{"ip": b["key"], "events": b["doc_count"]} for b in top_buckets],
        "drop_range":     drop_range,
        "sbl":            sbl,
        "lookback_days":  lookback_days,
        "query_hint":     f'src_ip:{drop_range} AND @timestamp:>=now-{lookback_days}d',
    }


def bucket_pivots(ip: str, identity: dict, observed: dict, external: dict) -> list:
    """
    Generate suggested next-step queries for the analyst. Returns a list of
    pivot dicts. Each pivot only appears if it would yield useful results
    (>= 1 distinct IP other than the current one).

    Self-IP filter (Layer 6 defense for pivots): IPs in TALLKITCHEN_SELF_IPS
    are filtered out of top_examples. Self-IPs belong to your own infra
    (droplet running T-Pot, WireGuard endpoints, etc.) — suggesting them as
    pivots would be noise that erodes analyst trust.
    """
    pivots = []

    # Same ASN — usually the highest-signal pivot for honeypot analysis
    p = _pivot_same_asn(ip, identity)
    if p:
        pivots.append(p)

    # Same country, recent window
    p = _pivot_same_country_recent(ip, identity)
    if p:
        pivots.append(p)

    # Same honeypot mix (toolkit profile)
    p = _pivot_same_honeypot_mix(ip, observed)
    if p:
        pivots.append(p)

    # Same Spamhaus DROP range (only fires if IN DROP; currently disabled
    # pending T-Pot Logstash mapping fix for IP-typed src_ip)
    p = _pivot_same_drop_range(ip, external)
    if p:
        pivots.append(p)

    # Apply self-IP filter to top_examples in each pivot
    if SELF_IPS:
        for p in pivots:
            originals = p.get("top_examples", []) or []
            filtered = [ex for ex in originals if ex.get("ip") not in SELF_IPS]
            n_removed = len(originals) - len(filtered)
            p["top_examples"] = filtered
            if n_removed > 0:
                p["self_ips_filtered"] = n_removed
                # Note: distinct_count is left as the ES-reported value.
                # The filter only removes self-IPs from the *top examples*;
                # the count may slightly overstate by the number of self-IPs
                # in the result, which is acceptable as long as we annotate.

    return pivots


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


def render_verdict(verdict: dict) -> None:
    """
    Render the VERDICT bucket FIRST — the analyst's primary question is "is this bad?"
    Display: large verdict label + score, then contribution breakdown, then conflicts.
    """
    if not verdict:
        return

    label = (verdict.get("verdict") or "unknown").upper()
    action = verdict.get("action") or "MONITOR"
    score = verdict.get("score", 0)

    # Color by verdict severity
    if label == "MALICIOUS":
        verdict_style = "bold white on red"
        action_style  = "bold red"
    elif label == "SUSPICIOUS":
        verdict_style = "bold black on yellow"
        action_style  = "bold yellow"
    elif label == "UNKNOWN":
        verdict_style = "bold white on blue"
        action_style  = "bold blue"
    else:  # BENIGN
        verdict_style = "bold black on green"
        action_style  = "bold green"

    console.print(f"[bold yellow]VERDICT[/]")
    console.print(f"  [{verdict_style}] {label} [/]  [dim]score[/] [bold]{score}/100[/]  →  [{action_style}]{action}[/]")

    # Contribution breakdown — which sources moved the needle
    contribs = verdict.get("contributions", {}) or {}
    if contribs:
        # Show only sources that actually contributed (non-zero)
        nonzero = [(k, v) for k, v in contribs.items() if abs(v) >= 0.1]
        nonzero.sort(key=lambda kv: abs(kv[1]), reverse=True)
        if nonzero:
            console.print("  [dim]Top contributing sources:[/]")
            for name, contribution in nonzero[:5]:
                if contribution > 0:
                    bar = "█" * min(20, int(abs(contribution)))
                    console.print(f"    [bold]{name:<14}[/] [red]{bar}[/] [bold]+{contribution:.1f}[/]")
                else:
                    bar = "█" * min(20, int(abs(contribution)))
                    console.print(f"    [bold]{name:<14}[/] [green]{bar}[/] [bold]{contribution:.1f}[/] [dim](anti-signal)[/]")

    # Floors applied (override rules that adjusted the score)
    floors = verdict.get("floors_applied", []) or []
    if floors:
        console.print("  [dim]Overrides applied:[/]")
        for f in floors:
            console.print(f"    [dim]·[/] {f}")

    # Cross-source conflicts (Layer 8 defense)
    conflicts = verdict.get("conflicts", []) or []
    if conflicts:
        console.print("  [bold yellow]⚠ Cross-source disagreement:[/]")
        for c in conflicts:
            console.print(f"    [yellow]·[/] {c}")

    if verdict.get("safety_brake"):
        console.print("  [dim](safety brake applied — verdict capped due to high-confidence anti-signal)[/]")

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


def render_external(external: dict, ioc: str) -> None:
    """
    Render the EXTERNAL bucket — one row per source queried.
    Each row: source name, one-line summary, link to open the source for that IOC.
    """
    if not external:
        return

    console.print("[bold yellow]EXTERNAL[/] [dim](public threat intel)[/]")
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_column(style="dim")

    # AbuseIPDB row
    ab = external.get("abuseipdb") or {}
    ab_link = f"https://www.abuseipdb.com/check/{ioc}"
    if not ab.get("available"):
        reason = ab.get("reason") or "no data"
        table.add_row("AbuseIPDB", f"[dim]not available — {reason}[/]", f"[link={ab_link}]open ↗[/]")
    else:
        score = ab.get("abuse_score", 0)
        reports = ab.get("total_reports", 0)
        if score >= 75:
            score_str = f"[bold red]{score}/100[/]"
        elif score >= 25:
            score_str = f"[bold yellow]{score}/100[/]"
        else:
            score_str = f"[bold green]{score}/100[/]"
        summary = f"{score_str} confidence, {reports} reports"
        if ab.get("is_whitelisted"):
            summary += " [dim](whitelisted)[/]"
        if ab.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("AbuseIPDB", summary, f"[link={ab_link}]open ↗[/]")

    # GreyNoise row
    gn = external.get("greynoise") or {}
    gn_link = f"https://viz.greynoise.io/ip/{ioc}"
    if not gn.get("available"):
        reason = gn.get("reason") or "no data"
        table.add_row("GreyNoise", f"[dim]not available — {reason}[/]", f"[link={gn_link}]open ↗[/]")
    else:
        cls = gn.get("classification", "unknown")
        name = gn.get("name")
        if cls == "malicious":
            cls_str = "[bold red]malicious[/]"
        elif cls == "benign":
            cls_str = "[bold green]benign[/]"
        else:
            cls_str = "[dim]unknown[/]"
        parts = [cls_str]
        if gn.get("noise"):
            parts.append("[yellow]noise[/]")
        if gn.get("riot"):
            parts.append("[cyan]known service (RIOT)[/]")
        if name:
            parts.append(f"\"{name}\"")
        summary = ", ".join(parts)
        if gn.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("GreyNoise", summary, f"[link={gn_link}]open ↗[/]")

    # VirusTotal row
    vt = external.get("virustotal") or {}
    vt_link = f"https://www.virustotal.com/gui/ip-address/{ioc}"
    if not vt.get("available"):
        reason = vt.get("reason") or "no data"
        table.add_row("VirusTotal", f"[dim]not available — {reason}[/]", f"[link={vt_link}]open ↗[/]")
    else:
        m = vt.get("malicious", 0)
        s = vt.get("suspicious", 0)
        total = vt.get("total_engines", 0)
        flagged = m + s
        if total == 0:
            ratio_str = "[dim]not analyzed[/]"
        elif flagged == 0:
            ratio_str = f"[green]0/{total}[/] flagged"
        elif (flagged / total) >= 0.10:
            ratio_str = f"[bold red]{flagged}/{total}[/] flagged"
        elif (flagged / total) >= 0.03:
            ratio_str = f"[yellow]{flagged}/{total}[/] flagged"
        else:
            ratio_str = f"[dim]{flagged}/{total}[/] flagged"
        rep = vt.get("reputation", 0)
        summary = ratio_str + (f"  rep: {rep}" if rep else "")
        if vt.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("VirusTotal", summary, f"[link={vt_link}]open ↗[/]")

    # OTX row
    otx = external.get("otx") or {}
    otx_link = f"https://otx.alienvault.com/indicator/ip/{ioc}"
    if not otx.get("available"):
        reason = otx.get("reason") or "no data"
        table.add_row("OTX", f"[dim]not available — {reason}[/]", f"[link={otx_link}]open ↗[/]")
    else:
        pc = otx.get("pulse_count", 0)
        if pc == 0:
            summary = "[dim]0 pulses[/]"
        elif pc >= 5:
            summary = f"[bold red]{pc} pulses[/]"
        elif pc >= 1:
            summary = f"[yellow]{pc} pulses[/]"
        top_pulses = otx.get("top_pulses") or []
        if top_pulses:
            summary += f" — \"{top_pulses[0]}\""
            if len(top_pulses) > 1:
                summary += f" +{len(top_pulses)-1} more"
        if otx.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("OTX", summary, f"[link={otx_link}]open ↗[/]")

    # ThreatFox row
    tf = external.get("threatfox") or {}
    tf_link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}"
    if not tf.get("available"):
        reason = tf.get("reason") or "no data"
        table.add_row("ThreatFox", f"[dim]not available — {reason}[/]", f"[link={tf_link}]open ↗[/]")
    else:
        mc = tf.get("match_count", 0)
        matches = tf.get("matches") or []
        if mc == 0:
            summary = "[dim]not in DB[/]"
        else:
            families = list({m["malware"] for m in matches if m.get("malware")})
            if families:
                summary = f"[bold red]{mc} matches[/] — " + ", ".join(families[:3])
                if len(families) > 3:
                    summary += f" +{len(families)-3} more"
            else:
                summary = f"[bold red]{mc} matches[/]"
        if tf.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("ThreatFox", summary, f"[link={tf_link}]open ↗[/]")

    # InternetDB row
    idb = external.get("internetdb") or {}
    idb_link = f"https://internetdb.shodan.io/{ioc}"
    if not idb.get("available"):
        reason = idb.get("reason") or "no data"
        table.add_row("InternetDB", f"[dim]not available — {reason}[/]", f"[link={idb_link}]open ↗[/]")
    else:
        ports = idb.get("ports", []) or []
        vulns = idb.get("vulns", []) or []
        tags  = idb.get("tags", []) or []
        if not ports:
            summary = "[dim]no scan data[/]"
        else:
            port_str = ", ".join(str(p) for p in ports[:8])
            if len(ports) > 8:
                port_str += f" +{len(ports)-8} more"
            summary = f"{len(ports)} ports: {port_str}"
            if vulns:
                summary += f"  [red]{len(vulns)} CVEs[/]"
            if tags:
                summary += f"  [yellow]tags: {', '.join(tags[:3])}[/]"
        if idb.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("InternetDB", summary, f"[link={idb_link}]open ↗[/]")

    # Spamhaus DROP row
    sh = external.get("spamhaus_drop") or {}
    sh_link = "https://www.spamhaus.org/drop/"
    if not sh.get("available"):
        reason = sh.get("reason") or "no data"
        table.add_row("Spamhaus DROP", f"[dim]not available — {reason}[/]", f"[link={sh_link}]open ↗[/]")
    else:
        if sh.get("in_drop"):
            summary = f"[bold red on yellow] IN DROP [/]  range {sh.get('range')}  ({sh.get('sbl')})"
        else:
            summary = "[dim]not listed[/]"
        if sh.get("_cached"):
            summary += " [dim](cached)[/]"
        table.add_row("Spamhaus DROP", summary, f"[link={sh_link}]open ↗[/]")

    console.print(table)
    console.print()


def render_rules(rules_data: dict) -> None:
    """
    Render the RULES bucket — what Water detection rules cover this attacker's
    likely behavior. Read-only metadata view, no execution, no modification.
    """
    if not rules_data:
        return

    techniques = rules_data.get("inferred_techniques", []) or []
    matches = rules_data.get("matching_rules", []) or []
    self_triggered = rules_data.get("self_triggered_rules", []) or []

    # If we couldn't even infer a technique, skip the bucket entirely
    if not techniques:
        return

    console.print("[bold yellow]RULES[/] [dim](Water detection coverage)[/]")
    tech_str = ", ".join(techniques[:3])
    console.print(f"  [dim]Attacker behavior suggests:[/] [bold]{tech_str}[/]")

    if not matches:
        console.print(f"  [yellow]No existing Water rules cover these techniques.[/] "
                      f"[dim](coverage gap — consider deploying detection)[/]")
        console.print()
        return

    # Group: hunt-triggered (pending_review) first, then production
    pending = [r for r in matches if r.get("is_hunt_triggered")]
    production = [r for r in matches if not r.get("is_hunt_triggered")]

    if pending:
        console.print(f"  [bold magenta]{len(pending)} pending review[/] "
                      f"[dim](hunt-triggered, awaiting analyst approval)[/]")
        for rule in pending[:5]:
            title = (rule.get("title") or "?")[:70]
            techs = ", ".join(rule.get("techniques") or [])
            console.print(f"    [magenta]·[/] {title}  [dim]({techs})[/]")
            if rule.get("triggered_by_ioc"):
                triggered_ioc = rule["triggered_by_ioc"]
                hunt_id = (rule.get("triggered_by_hunt_id") or "")[:8]
                console.print(f"      [dim]triggered by hunt of[/] [bold]{triggered_ioc}[/] [dim]({hunt_id}…)[/]")
            console.print(f"      [dim]{rule['path']}[/]")

    if production:
        console.print(f"  [bold green]{len(production)} in production[/]")
        for rule in production[:5]:
            title = (rule.get("title") or "?")[:70]
            techs = ", ".join(rule.get("techniques") or [])
            level = rule.get("level", "?")
            console.print(f"    [green]·[/] {title}  [dim]({techs}, level={level})[/]")
            console.print(f"      [dim]{rule['path']}[/]")

    console.print()


def render_pivots(pivots: list) -> None:
    """
    Render the PIVOTS bucket — suggested next-step queries.
    Each pivot is a separate item: question, top examples, ES query hint.
    """
    if not pivots:
        return

    console.print("[bold yellow]PIVOTS[/] [dim](suggested next hunts)[/]")
    for p in pivots:
        question = p.get("question", "")
        count = p.get("distinct_count", 0)
        examples = p.get("top_examples", []) or []
        filtered_count = p.get("self_ips_filtered", 0)

        # Highlight pivot count if it's substantial
        if count >= 50:
            count_str = f"[bold red]{count}[/]"
        elif count >= 10:
            count_str = f"[bold yellow]{count}[/]"
        else:
            count_str = f"[bold]{count}[/]"

        console.print(f"  [bold cyan]·[/] {question}")
        if examples:
            console.print(f"    [dim]{count_str} distinct IPs.[/] Top by activity:")
            for ex in examples[:5]:
                console.print(f"      [dim]·[/] {ex['ip']:<18} [dim]{ex['events']} events[/]")
        else:
            # All top examples were self-IPs and got filtered
            console.print(f"    [dim]{count_str} distinct IPs (all top examples were filtered as self-IPs)[/]")
        if filtered_count:
            console.print(f"    [dim]({filtered_count} self-IPs filtered out)[/]")
        qh = p.get("query_hint")
        if qh:
            console.print(f"    [dim]Kibana KQL:[/] [dim italic]{qh}[/]")
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
        "ATT&CK mapping not yet implemented",
        "Only IPv4 IOCs supported — domains, hashes, URLs not yet routed",
        "Pattern detection on unknowns not yet implemented",
        "LLM narrative (STORY, NEXT STEPS) not yet implemented",
        "Water integration (closing the loop on rule generation) not yet wired",
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
    external = bucket_external_ip(conn, ioc)
    verdict  = bucket_verdict(observed, external)
    pivots   = bucket_pivots(ioc, identity, observed, external)
    rules    = bucket_rules(observed, ioc)
    duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

    # VERDICT renders FIRST — analyst's primary question is "is this bad?"
    render_verdict(verdict)
    render_identity(identity)
    render_observed(observed)
    render_external(external, ioc)
    render_rules(rules)
    render_pivots(pivots)
    render_honest_limits(ioc_type)

    # Record this hunt to memory (SQLite + ES)
    result = {
        "verdict":  verdict,
        "identity": identity,
        "observed": observed,
        "external": external,
        "pivots":   pivots,
        "rules":    rules,
    }
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
