"""Regression test for the MX snapshot fallback branch in
store_audit_snapshots reading the wrong key.

Bug: the fallback branch (used when raw_results["mx"]["records"] is
empty but mx_details is present) read d.get("host", "") out of each
mx_details entry. mx_details entries are produced with a "hostname"
key (mx_check.py:291), never "host", so mx_str was always empty and no
MX snapshot was ever stored via this path -- MX changes went
undetected for any caller that only populates mx_details.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dns_snapshots


def test_mx_fallback_stores_snapshot_from_hostname_key():
    raw_results = {
        "mx": {
            "records": [],
            "mx_details": [
                {"hostname": "mail.example.com", "priority": 10},
                {"hostname": "backup.example.com", "priority": 20},
            ],
        }
    }

    with patch.object(dns_snapshots, "store_snapshot") as mock_store:
        dns_snapshots.store_audit_snapshots("example.com", raw_results)

    mx_calls = [c for c in mock_store.call_args_list if c.args[1] == "mx"]
    assert len(mx_calls) == 1, "MX fallback branch must store exactly one snapshot"
    assert mx_calls[0].args[2] == "backup.example.com; mail.example.com"


def test_mx_fallback_stores_nothing_when_no_hostnames():
    raw_results = {"mx": {"records": [], "mx_details": [{"priority": 10}]}}

    with patch.object(dns_snapshots, "store_snapshot") as mock_store:
        dns_snapshots.store_audit_snapshots("example.com", raw_results)

    mx_calls = [c for c in mock_store.call_args_list if c.args[1] == "mx"]
    assert mx_calls == []
