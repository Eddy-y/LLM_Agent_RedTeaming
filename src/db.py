"""
db.py

SQLite database layer.

We store two core things:

1) fetch_log
   One row per API call or fetch attempt
   Includes where raw payload is stored on disk

2) extracted_items
   "Intermediate records" extracted from raw payloads
   This is what your partner can later feed into the local LLM normalizer

Why this design:
  you can rerun normalization without re-fetching
  you can debug by opening the raw files
  you can track what you collected and when
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Foreign keys on by default
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fetch_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL,
          package_name TEXT NOT NULL,
          source TEXT NOT NULL,
          endpoint TEXT NOT NULL,
          fetched_at_utc TEXT NOT NULL,
          http_status INTEGER,
          error TEXT,
          raw_path TEXT NOT NULL
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS extracted_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL,
          package_name TEXT NOT NULL,
          source TEXT NOT NULL,
          item_type TEXT NOT NULL,
          item_id TEXT,
          title TEXT,
          url TEXT,
          published_at TEXT,
          severity TEXT,
          raw_path TEXT NOT NULL,
          extracted_at_utc TEXT NOT NULL
        );
        """
    )

    conn.commit()


def insert_fetch_log(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    package_name: str,
    source: str,
    endpoint: str,
    fetched_at_utc: str,
    http_status: int | None,
    error: str | None,
    raw_path: str,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO fetch_log
          (run_id, package_name, source, endpoint, fetched_at_utc, http_status, error, raw_path)
        VALUES
          (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, package_name, source, endpoint, fetched_at_utc, http_status, error, raw_path),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_extracted_items(
    conn: sqlite3.Connection,
    rows: Iterable[dict[str, Any]],
) -> None:
    conn.executemany(
        """
        INSERT INTO extracted_items
          (run_id, package_name, source, item_type, item_id, title, url, published_at, severity, raw_path, extracted_at_utc)
        VALUES
          (:run_id, :package_name, :source, :item_type, :item_id, :title, :url, :published_at, :severity, :raw_path, :extracted_at_utc)
        """,
        list(rows),
    )
    conn.commit()
