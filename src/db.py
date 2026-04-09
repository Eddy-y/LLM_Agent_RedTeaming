"""
db.py

SQLite database layer.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


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
        CREATE TABLE IF NOT EXISTS normalized_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL,
          package_name TEXT NOT NULL,
          source TEXT NOT NULL,
          record_type TEXT,
          canonical_id TEXT,
          title TEXT,
          summary TEXT,
          severity TEXT,
          published_at TEXT,
          references_json TEXT,
          
          UNIQUE(canonical_id, package_name)
        );
        """
    )
    conn.commit()


def insert_normalized_batch(conn: sqlite3.Connection, run_id: str, package_name: str, rows: list[dict]):
    for row in rows:
        # Skip inserting if the normalizer triggered the Escape Hatch (canonical_id is null)
        if not row.get("canonical_id"):
            continue
            
        conn.execute(
            """
            INSERT OR REPLACE INTO normalized_items
              (run_id, package_name, source, record_type, canonical_id, title, summary, severity, published_at, references_json)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                package_name,
                row.get("source"),
                row.get("record_type"),
                row.get("canonical_id"),
                row.get("title"),
                row.get("summary"),
                row.get("severity"),
                row.get("published_at"),
                str(row.get("references", []))
            )
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
  