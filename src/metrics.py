"""
src/metrics.py
Tracks system performance and safety guardrail metrics for RQ1 - RQ4.
Migrated to Amazon RDS (PostgreSQL) for centralized research data collection.
"""
from datetime import datetime
from .db import get_db_connection

def _init_metrics_table(conn):
    """Ensures the evaluation_metrics table exists in RDS."""
    with conn.cursor() as cur:
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
            )
        """)
    conn.commit()

def log_metric(data: dict):
    """Inserts a single run's metrics into the RDS database."""
    conn = get_db_connection()
    if not conn:
        print("[!] Could not connect to database to log metrics.")
        return

    try:
        # Ensure table exists before inserting
        _init_metrics_table(conn)
        
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO evaluation_metrics (
                    evaluated_at,
                    package_target,
                    retrieval_latency_sec,
                    analysis_latency_sec,
                    total_latency_sec,
                    cves_correlated,
                    mitre_capec_linked,
                    guardrail_triggered,
                    total_steps
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                datetime.now(),
                data.get("package_target", "unknown"),
                round(data.get("retrieval_latency", 0.0), 3),
                round(data.get("analysis_latency", 0.0), 3),
                round(data.get("total_latency", 0.0), 3),
                data.get("cves_correlated", 0),
                data.get("mitre_capec_linked", 0),
                data.get("guardrail_triggered", False),
                data.get("total_steps", 0)
            ))
        conn.commit()
        
    except Exception as e:
        print(f"[!] Error logging metrics to RDS: {e}")
    finally:
        if conn:
            conn.close()