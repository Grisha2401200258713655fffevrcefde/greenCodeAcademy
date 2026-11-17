#!/usr/bin/env python3
"""Atomic SQLite backup: never alters the source database."""
import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def backup_sqlite(source: Path, destination_dir: Path) -> Path:
    source = source.resolve()
    if not source.is_file():
        raise ValueError(f"Source DB is missing: {source}")
    destination_dir.mkdir(parents=True, exist_ok=True)
    if not destination_dir.is_dir():
        raise ValueError("Destination is not a directory")

    name = "academy-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    final = destination_dir / (name + ".sqlite3")
    if final.exists():
        raise FileExistsError(str(final))
    pending = destination_dir / (name + ".pending")
    # Restrict database backup contents to the current user.
    fd = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as conn:
            with sqlite3.connect(pending) as out:
                conn.backup(out)
        with sqlite3.connect(f"file:{pending}?mode=ro", uri=True) as verify:
            status = verify.execute("PRAGMA quick_check").fetchone()
            if status is None or status[0] != "ok":
                raise RuntimeError(f"Backup verification failed: {status}")
        pending.rename(final)
        return final
    except BaseException:
        pending.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description="Verified SQLite backup")
    parser.add_argument("database", type=Path)
    parser.add_argument("destination_dir", type=Path)
    args = parser.parse_args()
    path = backup_sqlite(args.database, args.destination_dir)
    print("Backup created and verified:", path)


if __name__ == "__main__":
    main()
