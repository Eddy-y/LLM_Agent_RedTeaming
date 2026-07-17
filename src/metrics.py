"""
src/metrics.py
Tracks system performance, IR accuracy, and safety guardrail metrics for RQ1 - RQ4.
Migrated to Amazon RDS (PostgreSQL) for centralized research data collection.
"""
from datetime import datetime

try:
    from db import get_db_connection
except ImportError:
    from src.db import get_db_connection

def _init_metrics_table(conn):
    """Ensures the graph_execution_metrics table exists in RDS."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS graph_execution_metrics (
                id SERIAL PRIMARY KEY,
                evaluated_at TIMESTAMP NOT NULL,
                package_target VARCHAR(255) NOT NULL,
                prompt_version VARCHAR(50), 
                
                -- 1. Latency Metrics 
                retrieval_latency_sec REAL,
                analysis_latency_sec REAL,
                total_latency_sec REAL,
                update_latency_sec REAL, 
                
                -- 2. Ingestion & Schema (For Graph 1)
                ingestion_success BOOLEAN,
                schema_completeness REAL,
                
                -- 3. Information Retrieval (For Graph 2 & 3)
                precision_at_k REAL,
                recall_at_k REAL,
                f1_score_at_k REAL,
                link_precision REAL,
                
                -- 4. Augmentation & Guardrails (For Graph 5)
                cves_correlated INTEGER,
                mitre_capec_linked INTEGER,
                guardrail_triggered BOOLEAN,
                augmentation_correctness REAL, 
                citation_correctness REAL,
                hallucination_rate REAL,
                total_steps INTEGER
            )
        """)
    conn.commit()

def log_metric(data: dict):
    """Inserts a single run's comprehensive metrics into the RDS database."""
    conn = get_db_connection()
    if not conn:
        print("[!] Could not connect to database to log metrics.")
        return

    try:
        _init_metrics_table(conn)
        
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO graph_execution_metrics (
                    evaluated_at, package_target, prompt_version,
                    retrieval_latency_sec, analysis_latency_sec, total_latency_sec, update_latency_sec,
                    ingestion_success, schema_completeness,
                    precision_at_k, recall_at_k, f1_score_at_k, link_precision,
                    cves_correlated, mitre_capec_linked, guardrail_triggered,
                    augmentation_correctness, citation_correctness, hallucination_rate, total_steps
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
            """, (
                datetime.now(),
                data.get("package_target", "unknown"),
                data.get("prompt_version", "v1.0"),
                
                round(data.get("retrieval_latency", 0.0), 3),
                round(data.get("analysis_latency", 0.0), 3),
                round(data.get("total_latency", 0.0), 3),
                round(data.get("update_latency", 0.0), 3),
                
                data.get("ingestion_success", True),
                round(data.get("schema_completeness", 0.0), 3),
                
                round(data.get("precision_at_k", 0.0), 3),
                round(data.get("recall_at_k", 0.0), 3),
                round(data.get("f1_score_at_k", 0.0), 3),
                round(data.get("link_precision", 0.0), 3),
                
                data.get("cves_correlated", 0),
                data.get("mitre_capec_linked", 0),
                data.get("guardrail_triggered", False),
                
                # These might be NULL initially if we rely on Human-in-the-Loop grading later
                data.get("augmentation_correctness", None), 
                data.get("citation_correctness", None),
                data.get("hallucination_rate", None),
                data.get("total_steps", 0)
            ))
        conn.commit()
        
    except Exception as e:
        print(f"[!] Error logging metrics to RDS: {e}")
    finally:
        if conn:
            conn.close()