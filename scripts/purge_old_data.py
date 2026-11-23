#!/usr/bin/env python3
# =============================================================================
# Net-monit V12.4 — Weekly data purge script
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# =============================================================================
"""
purge_old_data.py
-----------------
Removes old monitoring data from the SQLite database to keep file size
manageable. Run weekly via cron or Windows Task Scheduler.

Defaults (configurable via CLI args):
  --metric-history-days  30   Keep 30 days of metric history
  --alert-days           90   Keep 90 days of alert log
  --audit-days           180  Keep 180 days of audit log
  --vacuum                    Run VACUUM after purge (reduces file size)

Usage:
  python3 purge_old_data.py
  python3 purge_old_data.py --metric-history-days 14 --alert-days 60 --vacuum
  python3 purge_old_data.py --dry-run        # show counts without deleting
"""
import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

# Locate DB relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
DB_PATH    = SCRIPT_DIR.parent / "data" / "monitor.db"


def connect():
    if not DB_PATH.exists():
        print(f"[ERROR] Database not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def purge(conn, table, ts_col, cutoff_ts, dry_run=False):
    count_row = conn.execute(
        f"SELECT COUNT(*) AS n FROM {table} WHERE {ts_col} < ?", (cutoff_ts,)
    ).fetchone()
    count = count_row["n"] if count_row else 0
    if not dry_run and count > 0:
        conn.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (cutoff_ts,))
        conn.commit()
    return count


def format_bytes(n):
    for unit in ("B","KB","MB","GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def main():
    parser = argparse.ArgumentParser(description="Net-monit V12.4 — weekly data purge")
    parser.add_argument("--metric-history-days", type=int, default=30,
                        help="Keep this many days of metric_history (default: 30)")
    parser.add_argument("--alert-days",          type=int, default=90,
                        help="Keep this many days of alert_log (default: 90)")
    parser.add_argument("--audit-days",          type=int, default=180,
                        help="Keep this many days of audit_log (default: 180)")
    parser.add_argument("--vacuum",              action="store_true",
                        help="Run VACUUM after purge to shrink DB file")
    parser.add_argument("--dry-run",             action="store_true",
                        help="Show what would be deleted without actually deleting")
    args = parser.parse_args()

    now      = time.time()
    metric_cutoff = now - args.metric_history_days * 86400
    alert_cutoff  = now - args.alert_days          * 86400
    audit_cutoff  = now - args.audit_days          * 86400

    conn     = connect()
    size_before = DB_PATH.stat().st_size

    print(f"Net-monit V12.4 — Data Purge {'(DRY RUN) ' if args.dry_run else ''}")
    print(f"Database : {DB_PATH}")
    print(f"Size     : {format_bytes(size_before)}")
    print()

    tables = [
        ("metric_history", "ts",         metric_cutoff, args.metric_history_days, "metric history"),
        ("alert_log",      "ts",         alert_cutoff,  args.alert_days,          "alert log"),
        ("audit_log",      "ts",         audit_cutoff,  args.audit_days,          "audit log"),
    ]

    total_deleted = 0
    for table, col, cutoff, days, label in tables:
        # Check table exists
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not exists:
            print(f"  {label:20s} — table not found (skipped)")
            continue
        n = purge(conn, table, col, cutoff, dry_run=args.dry_run)
        action = "would remove" if args.dry_run else "removed"
        print(f"  {label:20s} — {action} {n:>6,} rows older than {days} days")
        total_deleted += n

    print()
    if args.dry_run:
        print(f"DRY RUN complete. {total_deleted:,} rows would be deleted. Re-run without --dry-run to apply.")
    else:
        print(f"Purge complete. {total_deleted:,} rows deleted.")

    if args.vacuum and not args.dry_run:
        print("Running VACUUM…", end=" ", flush=True)
        conn.execute("VACUUM")
        conn.commit()
        size_after = DB_PATH.stat().st_size
        saved = size_before - size_after
        print(f"done. Size: {format_bytes(size_after)} (saved {format_bytes(max(0,saved))})")
    elif not args.dry_run:
        size_after = DB_PATH.stat().st_size
        print(f"DB size after purge : {format_bytes(size_after)}  (run with --vacuum to compact)")

    conn.close()


if __name__ == "__main__":
    main()
