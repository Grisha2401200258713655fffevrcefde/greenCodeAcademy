#!/usr/bin/env python3
"""Create a permission-restricted PostgreSQL custom archive with pg_dump.

Connection uses PGHOST/PGPORT/PGUSER/PGDATABASE/PGPASSWORD or .pgpass.
Do not pass credentials on command line. Never touches the source database.
"""
import argparse
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone


def backup_postgres(destination_dir: Path) -> Path:
    database = os.environ.get("PGDATABASE", "").strip()
    if not database:
        raise ValueError("Set PGDATABASE before running the backup")
    destination_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = "academy-pg-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = destination_dir / f"{name}.dump"
    pending = destination_dir / f"{name}.pending"
    if dest.exists():
        raise FileExistsError(str(dest))
    # The file is created with 0600 even under permissive umask.
    fd = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    try:
        subprocess.run(["pg_dump", "--format=custom", "--no-owner",
                        "--file", str(pending)], check=True,
                       stdout=subprocess.DEVNULL)
        check = subprocess.run(["pg_restore", "--list", str(pending)],
                               check=True, capture_output=True, text=True)
        if not check.stdout.strip():
            raise RuntimeError("pg_restore could not enumerate the dump")
        os.replace(pending, dest)
        return dest
    except BaseException:
        pending.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description="PostgreSQL backup: custom format")
    parser.add_argument("destination_dir", type=Path)
    args = parser.parse_args()
    print("PostgreSQL backup verified:", backup_postgres(args.destination_dir))


if __name__ == "__main__":
    main()
