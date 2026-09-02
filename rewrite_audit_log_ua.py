#!/usr/bin/env python3
"""
One-off: bring the stored audit log in line with the logging policy.

server.py now writes a browser and OS family plus a bot flag instead of the
raw user-agent string. History written before that change still holds the
raw string, so this rewrites audit.log and its rotated backups with the same
transformation: derive the bot flag from the full user agent, then replace
the ua field with coarse labels.

Order matters here for the same reason it matters in server.py. The flag has
to come off the raw string, because after the rewrite there is nothing left
to derive it from.

Originals are copied aside before anything is written. Lines that are not
JSON are carried through untouched rather than dropped, and an entry that
already carries a bot flag is left alone, so a second run changes nothing.

Usage:
    python3 rewrite_audit_log_ua.py [log_dir]

log_dir defaults to the LOG_DIR the app itself uses.
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import LOG_DIR
from ua_classify import is_bot, ua_summary


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _log_files(log_dir: Path):
    """audit.log plus its rotated backups, newest first.

    Only audit.log.N counts as a rotated backup. The glob would otherwise
    pick up this script's own audit.log.bak-<stamp> copies on a second run
    and rewrite the pristine originals.
    """
    if not log_dir.is_dir():
        return []
    rotated = sorted(
        (p for p in log_dir.glob("audit.log.*") if p.suffix.lstrip(".").isdigit()),
        key=lambda p: int(p.suffix.lstrip(".")),
    )
    return [f for f in [log_dir / "audit.log"] + rotated if f.is_file()]


def _rewrite_line(line: str):
    """Transform one log line. Returns (text, changed)."""
    stripped = line.strip()
    if not stripped:
        return line, False
    try:
        entry = json.loads(stripped)
    except ValueError:
        return line, False
    if not isinstance(entry, dict) or "bot" in entry:
        return line, False

    raw = entry.get("ua") or ""
    if not isinstance(raw, str):
        raw = ""

    # Derive first, then discard. Reversing these two lines destroys the
    # only input the bot flag has.
    bot = is_bot(raw)
    summary = ua_summary(raw)

    rebuilt = {}
    for key, value in entry.items():
        if key == "ua":
            rebuilt["ua"] = summary
            rebuilt["bot"] = bot
        else:
            rebuilt[key] = value
    if "ua" not in rebuilt:
        rebuilt["ua"] = summary
        rebuilt["bot"] = bot

    return json.dumps(rebuilt) + "\n", True


def rewrite(path: Path, stamp: str) -> None:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    backup = path.with_name("%s.bak-%s" % (path.name, stamp))
    shutil.copy2(str(path), str(backup))

    out = []
    changed = 0
    unparsed = 0
    for line in lines:
        text, was_changed = _rewrite_line(line)
        out.append(text)
        if was_changed:
            changed += 1
        elif line.strip():
            unparsed += 1

    tmp = path.with_name("%s.tmp-%s" % (path.name, stamp))
    with tmp.open("w", encoding="utf-8") as fh:
        fh.writelines(out)
    os.replace(str(tmp), str(path))

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        after = sum(1 for _ in fh)

    print("%s" % path)
    print("  backup      %s" % backup.name)
    print("  lines before %d, after %d" % (len(lines), after))
    print("  rewritten    %d" % changed)
    print("  left as-is   %d" % unparsed)


def main() -> int:
    log_dir = Path(sys.argv[1] if len(sys.argv) > 1 else LOG_DIR)
    files = _log_files(log_dir)
    if not files:
        print("No audit log found in %s" % log_dir)
        return 1

    stamp = _stamp()
    total_before = 0
    total_after = 0
    for path in files:
        before = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
        rewrite(path, stamp)
        after = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
        total_before += before
        total_after += after

    print("")
    print("%d file(s): %d lines before, %d after" % (len(files), total_before, total_after))
    if total_before != total_after:
        print("WARNING: line count changed, inspect the backups before deleting them")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
