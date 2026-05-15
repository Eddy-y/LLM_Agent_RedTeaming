"""
init_cloud_db.py
Run this script ONCE before deploying your AWS Lambda workers to provision 
the complete PostgreSQL schema on your Amazon RDS instance.
"""
from dotenv import load_dotenv
from src.db import get_db_connection

def provision_database():
    load_dotenv()
    
    conn = get_db_connection()
    if not conn:
        print("[!] FATAL: Could not connect to Amazon RDS. Check your environment variables.")
        return

    try:
        with conn.cursor() as cur:
            print("🚀 Provisioning Amazon RDS PostgreSQL Schema...")

            # 1. The Fetch Log (from db.py)
            print("   -> Creating 'fetch_log' table...")
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

            # 2. The Normalized Items (from db.py)
            print("   -> Creating 'normalized_items' table...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS normalized_items (
                  id SERIAL PRIMARY KEY,
                  run_id TEXT NOT NULL,
                  package_name TEXT NOT NULL,
                  source TEXT NOT NULL,
                  record_type TEXT NOT NULL,
                  canonical_id TEXT,
                  title TEXT,
                  summary TEXT,
                  severity TEXT,
                  published_at TEXT,
                  references_json TEXT,
                  UNIQUE(package_name, source, canonical_id)
                );
            """)

            # 3. The API Pagination State (from state.py)
            print("   -> Creating 'pipeline_state' table...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_state (
                    id VARCHAR(50) PRIMARY KEY,
                    offset_value INTEGER NOT NULL DEFAULT 0
                );
            """)
            # Insert the default trackers
            cur.execute("INSERT INTO pipeline_state (id, offset_value) VALUES ('mitre', 0) ON CONFLICT DO NOTHING")
            cur.execute("INSERT INTO pipeline_state (id, offset_value) VALUES ('capec', 0) ON CONFLICT DO NOTHING")

            # 4. The Research Metrics (from metrics.py)
            print("   -> Creating 'evaluation_metrics' table...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_metrics (
                    id SERIAL PRIMARY KEY,
                    evaluated_at TIMESTAMP NOT NULL,
                    package_target VARCHAR(255) NOT NULL,
                    retrieval_latency_sec REAL,
                    analysis_latency_sec REAL,
                    total_latency_sec REAL,
                    cves_correlated INTEGER,
                    mitre_capec_linked INTEGER,
                    guardrail_triggered BOOLEAN,
                    total_steps INTEGER
                );
            """)

        conn.commit()
        print("\n✅ Database provisioning complete! All tables are ready for ingestion.")

    except Exception as e:
        print(f"\n[!] Error provisioning database: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    provision_database()