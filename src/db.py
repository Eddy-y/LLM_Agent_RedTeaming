"""
db.py

SQLite database layer.
"""
import os
import json
import psycopg2
from psycopg2.extras import execute_values

def get_db_connection():
    """Connects to the Amazon RDS PostgreSQL instance."""
    try:
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            database=os.environ.get("DB_NAME", "postgres"),
            user=os.environ.get("DB_USER", "postgres"),
            password=os.environ.get("DB_PASSWORD", "local_dev_password")
        )
        return conn
    except Exception as e:
        print(f"[!] Database connection failed: {e}")
        return None

def init_db(conn):
    """Creates tables using PostgreSQL syntax."""
    with conn.cursor() as cur:
        # Create fetch_log with SERIAL auto-increment
        cur.execute("""
            CREATE TABLE IF NOT EXISTS fetch_log (
              id SERIAL PRIMARY KEY,
              run_id TEXT NOT NULL,
              package_name TEXT NOT NULL,
              source TEXT NOT NULL,
              endpoint TEXT NOT NULL,
              fetched_at_utc TEXT NOT NULL,
              http_status INTEGER,
              error TEXT,
              raw_path TEXT NOT NULL
            );
        """)

        # Create normalized_items with the UNIQUE constraint for upserts
        cur.execute("""
            CREATE TABLE IF NOT EXISTS normalized_items (
              id SERIAL PRIMARY KEY,
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
        """)
        conn.commit()

def insert_normalized_batch(conn, run_id, package_name, rows):
    """High-speed batch insertion using ON CONFLICT DO UPDATE (Upsert)."""
    if not rows:
        return

    # Skip inserting if the normalizer triggered the Escape Hatch (canonical_id is null)
    valid_rows = [r for r in rows if r.get("canonical_id")]
    if not valid_rows:
        return

    # PostgreSQL syntax for INSERT OR REPLACE
    query = """
        INSERT INTO normalized_items 
          (run_id, package_name, source, record_type, canonical_id, title, summary, severity, published_at, references_json)
        VALUES %s
        ON CONFLICT (canonical_id, package_name) 
        DO UPDATE SET 
          run_id = EXCLUDED.run_id,
          source = EXCLUDED.source,
          record_type = EXCLUDED.record_type,
          title = EXCLUDED.title,
          summary = EXCLUDED.summary,
          severity = EXCLUDED.severity,
          published_at = EXCLUDED.published_at,
          references_json = EXCLUDED.references_json
    """
    
    values = [
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
            json.dumps(row.get("references", [])) # Safely stringify the JSON
        )
        for row in valid_rows
    ]

    with conn.cursor() as cur:
        execute_values(cur, query, values)
        conn.commit()

def insert_fetch_log(conn, run_id, package_name, source, endpoint, fetched_at_utc, http_status, error, raw_path):
    """Inserts into fetch_log and returns the new ID using RETURNING."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO fetch_log
              (run_id, package_name, source, endpoint, fetched_at_utc, http_status, error, raw_path)
            VALUES
              (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (run_id, package_name, source, endpoint, fetched_at_utc, http_status, error, raw_path)
        )
        inserted_id = cur.fetchone()[0]
        conn.commit()
        return inserted_id