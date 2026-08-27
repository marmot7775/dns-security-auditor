import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tempfile

import dns_snapshots


def _use_temp_db(monkeypatch):
    """Point dns_snapshots at a fresh temp DB and drop any cached connection
    so the calling thread reconnects against it."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # let sqlite create it fresh
    monkeypatch.setattr(dns_snapshots, "_DB_PATH", path)
    dns_snapshots._local.conn = None
    return path


def _insert_tied_timestamp(conn, domain, record_type, value):
    conn.execute(
        "INSERT INTO dns_snapshots (domain, record_type, record_value, record_hash, timestamp) "
        "VALUES (?, ?, ?, ?, '2026-01-01 00:00:00')",
        (domain, record_type, value, dns_snapshots._hash(value)),
    )


def test_same_second_write_is_not_lost_to_a_timestamp_tie(monkeypatch):
    _use_temp_db(monkeypatch)
    domain = "example.com"
    record_type = "dmarc"

    # v1, v2 both land in the same CURRENT_TIMESTAMP second (forced directly
    # so the test doesn't depend on racing a real wall-clock second boundary).
    conn = dns_snapshots._get_conn()
    _insert_tied_timestamp(conn, domain, record_type, "v1")
    _insert_tied_timestamp(conn, domain, record_type, "v2")
    conn.commit()

    # A third write back to "v1" arrives in the same tied second. Its hash
    # matches the *first* row, not the most recent (v2) one -- without an
    # id tiebreaker, ORDER BY timestamp DESC LIMIT 1 could compare against
    # either tied row and wrongly treat this as unchanged.
    dns_snapshots.store_snapshot(domain, record_type, "v1")

    rows = conn.execute(
        "SELECT record_value FROM dns_snapshots WHERE domain = ? AND record_type = ? ORDER BY id",
        (domain, record_type),
    ).fetchall()
    assert [r["record_value"] for r in rows] == ["v1", "v2", "v1"], (
        "third same-second write was skipped as unchanged instead of stored"
    )


def test_get_history_breaks_timestamp_ties_by_id_desc(monkeypatch):
    _use_temp_db(monkeypatch)
    domain = "example.com"
    record_type = "dmarc"

    conn = dns_snapshots._get_conn()
    _insert_tied_timestamp(conn, domain, record_type, "v1")
    _insert_tied_timestamp(conn, domain, record_type, "v2")
    _insert_tied_timestamp(conn, domain, record_type, "v3")
    conn.commit()

    history = dns_snapshots.get_history(domain, record_type)
    assert [h["record_value"] for h in history] == ["v3", "v2", "v1"], (
        "get_history did not return newest-first for same-second writes"
    )
