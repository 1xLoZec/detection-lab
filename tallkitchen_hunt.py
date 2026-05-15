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

Phase 3 scope: Engine + transmission (memory) + external sources.
Memory layer: SQLite local cache + ES hunt-logs-* canonical record.
External (IPv4 only currently):
  - Per-IP API sources: AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox,
    Shodan InternetDB. Each fails gracefully if its API key is missing.
  - List-based source: Spamhaus DROP (no key, daily download + local CIDR check).
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
        "Only IPv4 IOCs supported — domains, hashes, URLs not yet routed",
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
    external = bucket_external_ip(conn, ioc)
    duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

    render_identity(identity)
    render_observed(observed)
    render_external(external, ioc)
    render_honest_limits(ioc_type)

    # Record this hunt to memory (SQLite + ES)
    result = {"identity": identity, "observed": observed, "external": external}
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
