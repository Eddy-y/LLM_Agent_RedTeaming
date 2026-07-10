"""
state.py
Manages pagination state for external APIs (MITRE, CAPEC, NVD, GitHub).
Migrated to PostgreSQL to ensure state persistence across stateless AWS Lambda workers.

Schema: pipeline_state (source, package_name, offset_value)
- Universal sources (MITRE, CAPEC): package_name = 'Universal'
- Per-package sources (NVD, GitHub): package_name = actual package name
"""

from src.db import get_db_connection, release_db_connection

def _init_state_table(conn):
    """Ensures the state tracking table exists in RDS with per-package schema."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_state (
                source VARCHAR(50) NOT NULL,
                package_name VARCHAR(100) NOT NULL,
                offset_value INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (source, package_name)
            )
        """)
        # Insert default rows for universal sources (MITRE/CAPEC)
        cur.execute("""
            INSERT INTO pipeline_state (source, package_name, offset_value)
            VALUES ('mitre', 'Universal', 0)
            ON CONFLICT DO NOTHING
        """)
        cur.execute("""
            INSERT INTO pipeline_state (source, package_name, offset_value)
            VALUES ('capec', 'Universal', 0)
            ON CONFLICT DO NOTHING
        """)
    conn.commit()

def load_universal_state():
    """
    Retrieves offsets for universal sources (MITRE, CAPEC).
    Returns: {'mitre_offset': int, 'capec_offset': int}
    """
    conn = get_db_connection()
    if not conn:
        return {"mitre_offset": 0, "capec_offset": 0}

    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source, offset_value
                FROM pipeline_state
                WHERE package_name = 'Universal'
            """)
            rows = cur.fetchall()
            return {f"{row[0]}_offset": row[1] for row in rows}
    except Exception as e:
        print(f"[!] Error loading universal state from RDS: {e}")
        return {"mitre_offset": 0, "capec_offset": 0}
    finally:
        release_db_connection(conn)

def load_package_state(package_name: str, source: str) -> int:
    """
    Retrieves offset for a specific (source, package) pair.
    Returns: offset_value (int)
    """
    conn = get_db_connection()
    if not conn:
        return 0

    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT offset_value
                FROM pipeline_state
                WHERE source = %s AND package_name = %s
            """, (source, package_name))
            row = cur.fetchone()
            return row[0] if row else 0
    except Exception as e:
        print(f"[!] Error loading state for {source}/{package_name}: {e}")
        return 0
    finally:
        release_db_connection(conn)

def advance_package_offset(package_name: str, source: str, batch_size: int):
    """
    Atomically increments offset for a specific (source, package) pair.
    Creates the row if it doesn't exist.
    """
    conn = get_db_connection()
    if not conn:
        return

    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            # Upsert: insert if not exists, update if exists
            cur.execute("""
                INSERT INTO pipeline_state (source, package_name, offset_value)
                VALUES (%s, %s, %s)
                ON CONFLICT (source, package_name)
                DO UPDATE SET offset_value = pipeline_state.offset_value + %s
            """, (source, package_name, batch_size, batch_size))
        conn.commit()
    except Exception as e:
        print(f"[!] Error advancing {source}/{package_name} state: {e}")
    finally:
        release_db_connection(conn)

def advance_universal_offset(source: str, batch_size: int):
    """
    Atomically increments offset for universal sources (MITRE, CAPEC).
    """
    advance_package_offset('Universal', source, batch_size)

# Convenience functions for universal sources
def advance_mitre_offset(batch_size: int):
    advance_universal_offset('mitre', batch_size)

def advance_capec_offset(batch_size: int):
    advance_universal_offset('capec', batch_size)

# Convenience functions for per-package sources
def advance_nvd_offset(package_name: str, batch_size: int):
    """Advance NVD pagination offset for a specific package."""
    advance_package_offset(package_name, 'nvd', batch_size)

def advance_github_offset(package_name: str, batch_size: int):
    """Advance GitHub Advisories page count for a specific package."""
    advance_package_offset(package_name, 'github_advisories', batch_size)

def reset_package_state(package_name: str, source: str):
    """Reset pagination state for a specific (source, package) pair."""
    conn = get_db_connection()
    if not conn:
        print("[!] Cannot reset state: DB connection unavailable")
        return

    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE pipeline_state
                SET offset_value = 0
                WHERE source = %s AND package_name = %s
            """, (source, package_name))
        conn.commit()
        print(f"[OK] Reset {source}/{package_name} state to offset 0")
    except Exception as e:
        print(f"[!] Error resetting {source}/{package_name} state: {e}")
    finally:
        release_db_connection(conn)

def reset_all_states():
    """Reset all pagination states to 0."""
    conn = get_db_connection()
    if not conn:
        print("[!] Cannot reset state: DB connection unavailable")
        return

    try:
        _init_state_table(conn)
        with conn.cursor() as cur:
            cur.execute("UPDATE pipeline_state SET offset_value = 0")
        conn.commit()
        print(f"[OK] Reset all pagination states to offset 0")
    except Exception as e:
        print(f"[!] Error resetting all states: {e}")
    finally:
        release_db_connection(conn)
