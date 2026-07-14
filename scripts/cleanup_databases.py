"""
cleanup_databases.py

Cleans PostgreSQL and provides Neo4j cleanup commands.
Run this BEFORE re-ingesting data with fresh embeddings.

Usage: python cleanup_databases.py
"""

import sys
sys.path.insert(0, '.')

from src.db import get_db_connection, release_db_connection

def cleanup_postgresql():
    """Truncate all threat intelligence tables and reset pagination state."""
    print("=" * 70)
    print("POSTGRESQL DATABASE CLEANUP")
    print("=" * 70)

    conn = get_db_connection()
    if not conn:
        print("[ERROR] Could not connect to PostgreSQL database")
        return False

    try:
        with conn.cursor() as cur:
            # Show current record counts
            print("\n[1/3] Current record counts:")
            cur.execute("SELECT COUNT(*) FROM threat_intelligence_records")
            threat_count = cur.fetchone()[0]
            print(f"  - threat_intelligence_records: {threat_count}")

            cur.execute("SELECT COUNT(*) FROM url_validation_logs")
            url_count = cur.fetchone()[0]
            print(f"  - url_validation_logs: {url_count}")

            cur.execute("SELECT COUNT(*) FROM summary_verification_logs")
            summary_count = cur.fetchone()[0]
            print(f"  - summary_verification_logs: {summary_count}")

            cur.execute("SELECT COUNT(*) FROM graph_execution_metrics")
            metrics_count = cur.fetchone()[0]
            print(f"  - graph_execution_metrics: {metrics_count}")

            cur.execute("SELECT COUNT(*) FROM ingestion_logs")
            ingestion_count = cur.fetchone()[0]
            print(f"  - ingestion_logs: {ingestion_count}")

            # Show pagination state
            print("\n  Current pagination state:")
            cur.execute("SELECT source, package_name, offset_value FROM pipeline_state ORDER BY source, package_name")
            for row in cur.fetchall():
                print(f"    {row[0]:20} | {row[1]:15} | offset={row[2]}")

            # Confirm deletion
            print("\n" + "=" * 70)
            response = input("Are you sure you want to DELETE all this data? (type 'yes' to confirm): ")
            if response.lower() != 'yes':
                print("\n[CANCELLED] Database cleanup aborted.")
                return False

            print("\n[2/3] Truncating tables...")
            tables = [
                'threat_intelligence_records',
                'url_validation_logs',
                'summary_verification_logs',
                'graph_execution_metrics',
                'ingestion_logs'
            ]

            for table in tables:
                cur.execute(f"TRUNCATE TABLE {table} CASCADE")
                print(f"  [OK] Truncated {table}")

            print("\n[3/3] Resetting pagination state...")
            cur.execute("UPDATE pipeline_state SET offset_value = 0")
            rows_updated = cur.rowcount
            print(f"  [OK] Reset {rows_updated} pagination offsets to 0")

        conn.commit()

        # Verify cleanup
        print("\n[VERIFY] Post-cleanup verification:")
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM threat_intelligence_records")
            count = cur.fetchone()[0]
            print(f"  - threat_intelligence_records: {count} (should be 0)")

            cur.execute("SELECT source, package_name, offset_value FROM pipeline_state ORDER BY source, package_name")
            print("  - Pagination state:")
            for row in cur.fetchall():
                print(f"    {row[0]:20} | {row[1]:15} | offset={row[2]}")

        print("\n" + "=" * 70)
        print("[SUCCESS] PostgreSQL database cleaned successfully!")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"\n[ERROR] Failed to clean database: {e}")
        conn.rollback()
        return False
    finally:
        release_db_connection(conn)

def print_neo4j_cleanup_commands():
    """Print Neo4j cleanup commands for user to run manually."""
    print("\n" + "=" * 70)
    print("NEO4J GRAPH DATABASE CLEANUP")
    print("=" * 70)
    print("\nNeo4j requires manual cleanup. Please follow these steps:")
    print("\n1. Open Neo4j Browser or Neo4j Desktop")
    print("2. Connect to your Neo4j Aura instance")
    print("3. Run the following Cypher queries:\n")

    print("   // Delete all nodes and relationships")
    print("   MATCH (n) DETACH DELETE n;\n")

    print("   // Verify cleanup (should return 0)")
    print("   MATCH (n) RETURN count(n);\n")

    print("4. Confirm that the count is 0\n")
    print("=" * 70)

if __name__ == "__main__":
    print("\n")
    print("*" * 70)
    print("DATABASE CLEANUP SCRIPT")
    print("*" * 70)
    print("\nThis script will:")
    print("  1. Delete ALL threat intelligence records from PostgreSQL")
    print("  2. Reset all pagination offsets to 0")
    print("  3. Provide Neo4j cleanup commands")
    print("\nWARNING: This action CANNOT be undone!")
    print("*" * 70)
    print("\n")

    # Cleanup PostgreSQL
    success = cleanup_postgresql()

    if success:
        # Print Neo4j cleanup commands
        print_neo4j_cleanup_commands()

        print("\n[NEXT STEP] After cleaning Neo4j, run:")
        print("  python scripts/batch_ingestion.py --runs 50")
        print("\n")
    else:
        print("\n[FAILED] Cleanup incomplete. Please fix errors and try again.\n")
        sys.exit(1)
