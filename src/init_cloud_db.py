from dotenv import load_dotenv
from src.db import get_db_connection, release_db_connection

def provision_database():
    load_dotenv()
    conn = get_db_connection()
    if not conn:
        print("[!] FATAL: Could not connect to Amazon RDS.")
        return

    try:
        with conn.cursor() as cur:
            print("🚀 Provisioning Amazon RDS PostgreSQL Schema...")
            # Enable pgvector extension for semantic search (RQ2)
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fetch_log (
                  id SERIAL PRIMARY KEY, run_id TEXT NOT NULL, package_name TEXT NOT NULL,
                  source TEXT NOT NULL, endpoint TEXT NOT NULL, fetched_at_utc TEXT NOT NULL,
                  http_status INTEGER, error TEXT, raw_path TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS normalized_items (
                  id SERIAL PRIMARY KEY, run_id TEXT NOT NULL, package_name TEXT NOT NULL,
                  source TEXT NOT NULL, record_type TEXT NOT NULL, canonical_id TEXT,
                  title TEXT, summary TEXT, severity TEXT, published_at TEXT,
                  references_json TEXT, embedding vector(1536),
                  UNIQUE(package_name, source, canonical_id)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS evaluation_metrics (
                    id SERIAL PRIMARY KEY, evaluated_at TIMESTAMP NOT NULL,
                    package_target VARCHAR(255) NOT NULL, retrieval_latency_sec REAL,
                    analysis_latency_sec REAL, total_latency_sec REAL,
                    cves_correlated INTEGER, mitre_capec_linked INTEGER,
                    guardrail_triggered BOOLEAN, total_steps INTEGER
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY, timestamp TIMESTAMP NOT NULL,
                    file_origin TEXT, agent_name TEXT, hallucination_detected BOOLEAN,
                    hallucination_reason TEXT, url_validation_json TEXT
                );
            """)
        conn.commit()
        print("\n✅ Database provisioning complete!")
    except Exception as e:
        print(f"\n[!] Error provisioning database: {e}")
        conn.rollback()
    finally:
        release_db_connection(conn)

if __name__ == "__main__":
    provision_database()