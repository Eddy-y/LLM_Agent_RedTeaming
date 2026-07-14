"""
Quick status check for Knowledge Graph components.
Run this first to see if your GraphRAG setup is working.

Usage:
    python test/check_graph_status.py
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def check_neo4j():
    """Check Neo4j connection and data."""
    print("\n" + "="*60)
    print("🔍 Checking Neo4j...")
    print("="*60)

    try:
        from src.graph_db import get_neo4j_session

        with get_neo4j_session() as session:
            # Quick count
            result = session.run("MATCH (n) RETURN count(n) AS total")
            total = result.single()["total"]

            result = session.run("MATCH ()-[r]->() RETURN count(r) AS total")
            total_rels = result.single()["total"]

            print(f"✅ Connected to Neo4j")
            print(f"   Nodes: {total}")
            print(f"   Relationships: {total_rels}")

            if total == 0:
                print("\n⚠️  Graph is EMPTY - run ingestion pipeline first")
                return False

            # Show node types
            result = session.run("""
                MATCH (n)
                RETURN labels(n)[0] AS type, count(n) AS count
                ORDER BY count DESC
                LIMIT 5
            """)

            print(f"\n   Top node types:")
            for record in result:
                print(f"      {record['type']}: {record['count']}")

            return True

    except Exception as e:
        print(f"❌ Neo4j connection failed: {e}")
        print("\n   Troubleshooting:")
        print("   1. Check .env: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD")
        print("   2. Verify Neo4j Aura instance is active")
        return False


def check_postgresql():
    """Check PostgreSQL connection and embeddings."""
    print("\n" + "="*60)
    print("🔍 Checking PostgreSQL...")
    print("="*60)

    try:
        from src.db import get_db_connection, release_db_connection

        conn = get_db_connection()
        if not conn:
            print("❌ Could not connect to PostgreSQL")
            return False

        cursor = conn.cursor()

        # Count records
        cursor.execute("SELECT COUNT(*) FROM threat_intelligence_records")
        total = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM threat_intelligence_records
            WHERE embedding IS NOT NULL
        """)
        with_embeddings = cursor.fetchone()[0]

        print(f"✅ Connected to PostgreSQL")
        print(f"   Total records: {total}")
        print(f"   With embeddings: {with_embeddings} ({with_embeddings/total*100:.1f}%)" if total > 0 else "   With embeddings: 0")

        if total == 0:
            print("\n⚠️  Database is EMPTY - run ingestion pipeline first")
            release_db_connection(conn)
            return False

        if with_embeddings == 0:
            print("\n⚠️  No embeddings found - vector search will not work")
            print("   Embeddings are generated during ingestion")

        # Sample record
        cursor.execute("""
            SELECT canonical_id, source, severity
            FROM threat_intelligence_records
            LIMIT 1
        """)
        sample = cursor.fetchone()
        if sample:
            print(f"\n   Sample record: {sample[0]} ({sample[1]}, {sample[2]})")

        release_db_connection(conn)
        return True

    except Exception as e:
        print(f"❌ PostgreSQL check failed: {e}")
        return False


def check_retrieval():
    """Test hybrid retrieval with a sample query."""
    print("\n" + "="*60)
    print("🔍 Testing Hybrid Retrieval...")
    print("="*60)

    try:
        from graph_agents import hybrid_retrieval

        # Simple test query
        query = "SQL injection"
        print(f"\n   Query: '{query}'")

        results = hybrid_retrieval(query, package_name="test")

        if not results or len(results) < 50:
            print("⚠️  No results returned (database may be empty)")
            return False

        # Count entities
        lines = results.split('\n')
        entities = [l for l in lines if l.strip().startswith('[')]

        print(f"✅ Hybrid retrieval working")
        print(f"   Retrieved {len(entities)} entities")

        # Count by method
        vector_count = len([l for l in lines if '[vector_search]' in l])
        graph_count = len([l for l in lines if '[graph_traversal]' in l])

        print(f"\n   Methods used:")
        print(f"      Vector search: {vector_count} entities")
        print(f"      Graph traversal: {graph_count} entities")

        if vector_count == 0:
            print("\n   ⚠️  Vector search not used (embeddings missing?)")

        if graph_count == 0:
            print("\n   ⚠️  Graph traversal not used (Neo4j empty?)")

        # Show first entity
        if entities:
            print(f"\n   Sample entity:")
            print(f"      {entities[0][:100]}...")

        return True

    except Exception as e:
        print(f"❌ Retrieval test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all status checks."""
    print("""
============================================================
     Knowledge Graph Status Check
============================================================
    """)

    results = {}

    # Check each component
    results['postgresql'] = check_postgresql()
    results['neo4j'] = check_neo4j()
    results['retrieval'] = check_retrieval()

    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)

    all_ok = all(results.values())

    for component, status in results.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {component.upper()}: {'OK' if status else 'FAILED'}")

    if all_ok:
        print("\n🎉 All systems operational!")
        print("\nNext steps:")
        print("   • Run: python test/test_knowledge_graph_retrieval.py")
        print("   • Test UI: streamlit run app_dashboard.py")
    else:
        print("\n⚠️  Some components need attention")
        print("\nTroubleshooting:")

        if not results['postgresql']:
            print("\n   PostgreSQL:")
            print("      • Run: python scripts/init_cloud_db.py")
            print("      • Run: python scripts/ingest_to_sqs.py")

        if not results['neo4j']:
            print("\n   Neo4j:")
            print("      • Check .env credentials")
            print("      • Run: python scripts/init_neo4j_schema.py")
            print("      • Run: python test/run_worker.py")

        if not results['retrieval']:
            print("\n   Retrieval:")
            print("      • Ensure data exists in both PostgreSQL and Neo4j")
            print("      • Check embeddings are populated")


if __name__ == "__main__":
    main()
