"""
DNS Snapshot Storage
====================
Lightweight SQLite-based storage for tracking changes to public DNS records
over time. Only stores a new snapshot when a record actually changes.

All data stored is publicly available DNS records.
No personal data, IP addresses, or user tracking.
"""

import hashlib
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_snapshots.db")
_RETENTION_DAYS = 90

# Thread-local connections (SQLite is not thread-safe by default)
_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(_DB_PATH, timeout=5)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _init_db(_local.conn)
    return _local.conn


def _init_db(conn: sqlite3.Connection):
    """Create the schema if it does not exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS dns_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL,
            record_value TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_domain_type
            ON dns_snapshots(domain, record_type);
        CREATE INDEX IF NOT EXISTS idx_timestamp
            ON dns_snapshots(timestamp);
    """)


def _hash(value: str) -> str:
    """SHA-256 hash of a record value for fast comparison."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def store_snapshot(domain: str, record_type: str, record_value: str):
    """Store a DNS record snapshot if it has changed since the last one.

    Does nothing if the latest snapshot for this domain+type has the same hash.
    """
    if not record_value:
        return
    domain = domain.lower().strip()
    record_type = record_type.lower().strip()
    h = _hash(record_value)

    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT record_hash FROM dns_snapshots "
            "WHERE domain = ? AND record_type = ? "
            "ORDER BY timestamp DESC LIMIT 1",
            (domain, record_type),
        ).fetchone()

        if row and row["record_hash"] == h:
            return  # No change

        conn.execute(
            "INSERT INTO dns_snapshots (domain, record_type, record_value, record_hash) "
            "VALUES (?, ?, ?, ?)",
            (domain, record_type, record_value, h),
        )
        conn.commit()
    except Exception as e:
        log.debug("Snapshot store failed: %s", e)


def store_audit_snapshots(domain: str, raw_results: Dict[str, Any]):
    """Store snapshots for all records discovered during an audit.

    Extracts records from the raw_results dict produced by audit checks.
    """
    domain = domain.lower().strip()

    # DMARC
    dmarc = raw_results.get("dmarc", {})
    if dmarc.get("record"):
        store_snapshot(domain, "dmarc", dmarc["record"])

    # SPF
    spf = raw_results.get("spf", {})
    if spf.get("record"):
        store_snapshot(domain, "spf", spf["record"])

    # MX (join sorted MX hosts as a single string for hashing)
    mx = raw_results.get("mx", {})
    mx_records = mx.get("records") or []
    mx_details = mx.get("mx_details") or []
    if mx_records:
        mx_str = "; ".join(sorted(mx_records))
        store_snapshot(domain, "mx", mx_str)
    elif mx_details:
        mx_str = "; ".join(sorted(d.get("host", "") for d in mx_details if d.get("host")))
        if mx_str:
            store_snapshot(domain, "mx", mx_str)

    # DKIM (store each discovered selector's record)
    dkim = raw_results.get("dkim", {})
    for sel in dkim.get("found_selectors", []):
        selector_name = sel.get("selector", "")
        record = sel.get("record", "")
        if selector_name and record:
            store_snapshot(domain, f"dkim:{selector_name}", record)

    # MTA-STS
    mta_sts = raw_results.get("mta_sts", {})
    if mta_sts.get("txt_record"):
        store_snapshot(domain, "mta-sts", mta_sts["txt_record"])

    # TLS-RPT
    tls_rpt = raw_results.get("tls_rpt", {})
    if tls_rpt.get("record"):
        store_snapshot(domain, "tls-rpt", tls_rpt["record"])

    # DANE (store per MX host)
    dane = raw_results.get("dane", {})
    for tlsa in dane.get("tlsa_records", []):
        mx_host = tlsa.get("mx_host", "")
        record = tlsa.get("record", "")
        if mx_host and record:
            store_snapshot(domain, f"dane:{mx_host}", record)

    # DNSSEC
    dnssec = raw_results.get("dnssec", {})
    if dnssec.get("dnskey_record"):
        store_snapshot(domain, "dnssec", dnssec["dnskey_record"])

    # CAA
    caa = raw_results.get("caa", {})
    caa_records = caa.get("records") or []
    if caa_records:
        caa_str = "; ".join(sorted(caa_records))
        store_snapshot(domain, "caa", caa_str)

    # Nameservers
    ns = raw_results.get("nameservers", {})
    ns_list = ns.get("nameservers") or []
    if ns_list:
        ns_str = "; ".join(sorted(ns_list))
        store_snapshot(domain, "nameservers", ns_str)


def get_history(domain: str, record_type: str, limit: int = 10) -> List[Dict]:
    """Get the change history for a domain+record_type.

    Returns a list of snapshots ordered newest-first, limited to `limit` entries.
    """
    domain = domain.lower().strip()
    record_type = record_type.lower().strip()
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT record_value, record_hash, timestamp "
            "FROM dns_snapshots "
            "WHERE domain = ? AND record_type = ? "
            "ORDER BY timestamp DESC LIMIT ?",
            (domain, record_type, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log.debug("History fetch failed: %s", e)
        return []


def get_all_history(domain: str, limit_per_type: int = 5) -> Dict[str, List[Dict]]:
    """Get change history for all record types for a domain.

    Returns a dict keyed by record_type, each containing a list of snapshots.
    """
    domain = domain.lower().strip()
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT record_type, record_value, record_hash, timestamp "
            "FROM dns_snapshots "
            "WHERE domain = ? "
            "ORDER BY record_type, timestamp DESC",
            (domain,),
        ).fetchall()

        history: Dict[str, List[Dict]] = {}
        for r in rows:
            rt = r["record_type"]
            if rt not in history:
                history[rt] = []
            if len(history[rt]) < limit_per_type:
                history[rt].append({
                    "record_value": r["record_value"],
                    "record_hash": r["record_hash"],
                    "timestamp": r["timestamp"],
                })
        return history
    except Exception as e:
        log.debug("All history fetch failed: %s", e)
        return {}


def get_first_seen(domain: str) -> Optional[str]:
    """Get the timestamp of the earliest snapshot for a domain."""
    domain = domain.lower().strip()
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT MIN(timestamp) as first_seen FROM dns_snapshots WHERE domain = ?",
            (domain,),
        ).fetchone()
        if row and row["first_seen"]:
            return row["first_seen"]
        return None
    except Exception:
        return None


def purge_old_snapshots():
    """Remove snapshots older than _RETENTION_DAYS days."""
    try:
        conn = _get_conn()
        conn.execute(
            "DELETE FROM dns_snapshots WHERE timestamp < datetime('now', ?)",
            (f"-{_RETENTION_DAYS} days",),
        )
        conn.commit()
    except Exception as e:
        log.debug("Purge failed: %s", e)
