from dotenv import load_dotenv
from db import get_db_connection, release_db_connection

def provision_database():
    load_dotenv()
    conn = get_db_connection()
    if not conn:
        print("[!] FATAL: Could not connect to Amazon RDS.")
        return

    try:
        with conn.cursor() as cur:
            print("Provisioning Amazon RDS PostgreSQL Schema...")
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
                  verification_status VARCHAR(20), last_verified_at TIMESTAMP,
                  CONSTRAINT unique_canonical_package UNIQUE(canonical_id, package_name)
                );
            """)
            # Add verification columns if they don't exist (for existing databases)
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='normalized_items' AND column_name='verification_status'
                    ) THEN
                        ALTER TABLE normalized_items ADD COLUMN verification_status VARCHAR(20);
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='normalized_items' AND column_name='last_verified_at'
                    ) THEN
                        ALTER TABLE normalized_items ADD COLUMN last_verified_at TIMESTAMP;
                    END IF;
                END $$;
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_normalized_verification
                ON normalized_items(verification_status);
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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS verification_logs (
                    id SERIAL PRIMARY KEY,
                    normalized_item_id INTEGER NOT NULL,
                    verified_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    source_url TEXT NOT NULL,
                    scrape_status VARCHAR(50),
                    scraped_content TEXT,
                    http_status INTEGER,
                    keywords_llm TEXT[],
                    keywords_source TEXT[],
                    jaccard_score REAL,
                    fuzzy_score REAL,
                    combined_score REAL,
                    verdict VARCHAR(20),
                    error_msg TEXT,
                    FOREIGN KEY (normalized_item_id) REFERENCES normalized_items(id) ON DELETE CASCADE
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_verification_verdict
                ON verification_logs(verdict);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_verification_item
                ON verification_logs(normalized_item_id);
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_verification_score
                ON verification_logs(combined_score);
            """)
        conn.commit()
        print("\nDatabase provisioning complete!")
    except Exception as e:
        print(f"\n[!] Error provisioning database: {e}")
        conn.rollback()
    finally:
        release_db_connection(conn)

if __name__ == "__main__":
    provision_database()