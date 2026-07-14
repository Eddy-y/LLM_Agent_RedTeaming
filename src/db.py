import os
import json
import boto3
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import execute_values, RealDictCursor

# Load .env file for local development (not needed in Lambda)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # Running in Lambda, environment variables are provided by AWS 

def get_secure_password():
    """Fetches password from local .env or dynamically from AWS SSM."""
    # 1. If running locally, grab it straight from the .env file
    if "DB_PASSWORD" in os.environ:
        return os.environ["DB_PASSWORD"]
    
    # 2. If running in AWS Lambda, fetch it securely via boto3
    param_name = os.environ.get("DB_PASSWORD_PARAM")
    if param_name:
        ssm = boto3.client('ssm')
        response = ssm.get_parameter(Name=param_name, WithDecryption=True)
        return response['Parameter']['Value']
        
    return "local_dev_password" # Fallback

# Initialize a global connection pool
try:
    db_pool = ThreadedConnectionPool(
        minconn=1,
        maxconn=20,
        host=os.environ.get("DB_HOST", "localhost"),
        database=os.environ.get("DB_NAME", "postgres"),
        user=os.environ.get("DB_USER", "postgres"),
        password=get_secure_password(),
        sslmode="require"
    )
except Exception as e:
    print(f"[!] Failed to initialize database connection pool: {e}")
    db_pool = None

def get_db_connection():
    if db_pool:
        try:
            return db_pool.getconn()
        except Exception as e:
            print(f"[!] Pool exhausted or error: {e}")
            return None
    return None

def release_db_connection(conn):
    if db_pool and conn:
        db_pool.putconn(conn)

def insert_normalized_batch(conn, run_id, package_name, rows):
    """
    Insert normalized threat intelligence records into PostgreSQL.

    Supports optional embedding vectors for semantic search.
    If a row contains an 'embedding' key with a list of floats, it will be
    inserted into the embedding column for pgvector similarity search.

    Args:
        conn: PostgreSQL connection
        run_id: Ingestion run identifier
        package_name: Package name
        rows: List of normalized record dicts (may include 'embedding' key)
    """
    if not rows: return
    valid_rows = [r for r in rows if r.get("canonical_id")]
    if not valid_rows: return

    # Check if any rows have embeddings
    has_embeddings = any(r.get("embedding") for r in valid_rows)

    if has_embeddings:
        # Query with embedding column
        query = """
            INSERT INTO threat_intelligence_records
              (run_id, package_name, source, record_type, canonical_id, title, summary,
               severity, published_at, references_json, embedding)
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
              references_json = EXCLUDED.references_json,
              embedding = EXCLUDED.embedding
        """
        values = [(
            run_id, package_name, row.get("source"), row.get("record_type"),
            row.get("canonical_id"), row.get("title"), row.get("summary"),
            row.get("severity"), row.get("published_at"),
            json.dumps(row.get("references", [])),
            row.get("embedding")  # Will be None if not present
        ) for row in valid_rows]
    else:
        # Original query without embedding (backward compatible)
        query = """
            INSERT INTO threat_intelligence_records
              (run_id, package_name, source, record_type, canonical_id, title, summary,
               severity, published_at, references_json)
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
        values = [(
            run_id, package_name, row.get("source"), row.get("record_type"),
            row.get("canonical_id"), row.get("title"), row.get("summary"),
            row.get("severity"), row.get("published_at"),
            json.dumps(row.get("references", []))
        ) for row in valid_rows]

    with conn.cursor() as cur:
        execute_values(cur, query, values)
        conn.commit()

def log_url_validation_event(conn, log_entry: dict):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO url_validation_logs (timestamp, file_origin, agent_name, hallucination_detected, hallucination_reason, url_validation_json)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            log_entry["timestamp"], log_entry["file_origin"], log_entry["agent_name"],
            log_entry["evaluation"]["hallucination_detected"],
            log_entry["evaluation"]["hallucination_reason"],
            json.dumps(log_entry["evaluation"]["url_validation"])
        ))
        conn.commit()

def get_unverified_records(conn, source: str, limit: int = 50):
    """
    Fetch unverified records from threat_intelligence_records for verification.
    Priority: never verified > failed verification > old verifications.

    Returns list of dicts with keys: id, canonical_id, summary, references_json
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, canonical_id, summary, references_json
            FROM threat_intelligence_records
            WHERE source = %s
            AND (
                verification_status IS NULL
                OR (last_verified_at < NOW() - INTERVAL '30 days' AND verification_status = 'MISMATCH')
            )
            ORDER BY id ASC
            LIMIT %s
        """, (source, limit))
        return cur.fetchall()

def insert_summary_verification_log(conn, log_data: dict):
    """
    Insert a verification log entry into summary_verification_logs table.

    Expected log_data keys:
    - threat_intel_record_id (int)
    - source_url (str)
    - scrape_status (str)
    - scraped_content (str or None)
    - http_status (int or None)
    - keywords_llm (list[str])
    - keywords_source (list[str])
    - jaccard_score (float or None)
    - fuzzy_score (float or None)
    - combined_score (float or None)
    - verdict (str)
    - error_msg (str or None)
    """
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO summary_verification_logs (
                threat_intel_record_id, source_url, scrape_status, scraped_content, http_status,
                keywords_llm, keywords_source, jaccard_score, fuzzy_score, combined_score,
                verdict, error_msg
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            log_data["threat_intel_record_id"], log_data["source_url"], log_data["scrape_status"],
            log_data.get("scraped_content"), log_data.get("http_status"),
            log_data.get("keywords_llm", []), log_data.get("keywords_source", []),
            log_data.get("jaccard_score"), log_data.get("fuzzy_score"),
            log_data.get("combined_score"), log_data["verdict"], log_data.get("error_msg")
        ))
        conn.commit()

def update_verification_status(conn, item_id: int, verdict: str):
    """
    Update verification_status and last_verified_at for a threat_intelligence_record.
    """
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE threat_intelligence_records
            SET verification_status = %s, last_verified_at = NOW()
            WHERE id = %s
        """, (verdict, item_id))
        conn.commit()

