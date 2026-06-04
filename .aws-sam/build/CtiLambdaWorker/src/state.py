"""
state.py
Manages pagination state for external APIs (MITRE, CAPEC).
Migrated to PostgreSQL to ensure state persistence across stateless AWS Lambda workers.
"""

from .db import get_db_connection

def _init_state_table(conn):
    """Ensures the state tracking table exists in RDS."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_state (
                id VARCHAR(50) PRIMARY KEY,
                offset_value INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Insert default rows if they don't exist
        cur.execute("INSERT INTO pipeline_state (id, offset_value) VALUES ('mitre', 0) ON CONFLICT DO NOTHING")
        cur.execute("INSERT INTO pipeline_state (id, offset_value) VALUES ('capec', 0) ON CONFLICT DO NOTHING")
    conn.commit()

def load_state():
    """Retrieves the current offsets from the cloud database."""
    conn = get_db_connection()
    if not conn:
        return {"mitre_offset": 0, "capec_offset": 0}
        
    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT id, offset_value FROM pipeline_state")
            rows = cur.fetchall()
            return {f"{row[0]}_offset": row[1] for row in rows}
    except Exception as e:
        print(f"[!] Error loading state from RDS: {e}")
        return {"mitre_offset": 0, "capec_offset": 0}
    finally:
        conn.close()

def _advance_offset(system: str, batch_size: int):
    """Helper to atomically increment offsets in the database."""
    conn = get_db_connection()
    if not conn:
        return
        
    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE pipeline_state 
                SET offset_value = offset_value + %s 
                WHERE id = %s
            """, (batch_size, system))
        conn.commit()
    except Exception as e:
        print(f"[!] Error updating {system} state in RDS: {e}")
    finally:
        conn.close()

def advance_mitre_offset(batch_size: int):
    _advance_offset('mitre', batch_size)

def advance_capec_offset(batch_size: int):
    _advance_offset('capec', batch_size)