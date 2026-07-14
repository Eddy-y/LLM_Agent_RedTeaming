"""
Interactive Knowledge Graph Retrieval Testing Script

This script helps you verify:
1. What data exists in Neo4j
2. What the hybrid retrieval returns for different queries
3. What information reaches the analyzer agent
4. The complete flow from user query → Neo4j → LLM → response

Usage:
    python test/test_knowledge_graph_retrieval.py
"""

import sys
import os
import json
from typing import Dict, List

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_db import get_neo4j_session
from src.db import get_db_connection, release_db_connection
from graph_agents import (
    hybrid_retrieval,
    semantic_vector_search,
    graph_traversal_search,
    fetch_semantic_cti_data
)


def print_section(title: str):
    """Pretty print section headers."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def check_neo4j_data():
    """
    Test 1: Inspect what data exists in Neo4j.
    Shows node counts, relationship counts, and sample data.
    """
    print_section("TEST 1: Neo4j Graph Data Inspection")

    try:
        with get_neo4j_session() as session:
            # Count nodes by type
            print("\n📊 Node Counts by Type:")
            node_query = """
            MATCH (n)
            RETURN labels(n)[0] AS node_type, COUNT(n) AS count
            ORDER BY count DESC
            """
            result = session.run(node_query)

            total_nodes = 0
            for record in result:
                node_type = record["node_type"]
                count = record["count"]
                total_nodes += count
                print(f"   {node_type}: {count} nodes")

            print(f"\n   TOTAL NODES: {total_nodes}")

            # Count relationships by type
            print("\n🔗 Relationship Counts by Type:")
            rel_query = """
            MATCH ()-[r]->()
            RETURN type(r) AS relationship_type, COUNT(r) AS count
            ORDER BY count DESC
            """
            result = session.run(rel_query)

            total_rels = 0
            for record in result:
                rel_type = record["relationship_type"]
                count = record["count"]
                total_rels += count
                print(f"   {rel_type}: {count} relationships")

            print(f"\n   TOTAL RELATIONSHIPS: {total_rels}")

            # Sample vulnerabilities
            print("\n🔍 Sample Vulnerabilities (first 5):")
            sample_query = """
            MATCH (v:Vulnerability)
            RETURN v.canonical_id AS id, v.severity AS severity,
                   v.title AS title, v.summary AS summary
            LIMIT 5
            """
            result = session.run(sample_query)

            for record in result:
                print(f"\n   ID: {record['id']}")
                print(f"   Severity: {record['severity']}")
                print(f"   Title: {record['title']}")
                print(f"   Summary: {record['summary'][:100]}...")

            # Check for connected vulnerabilities
            print("\n🕸️  Sample Connected Data (Vulnerability → Weakness):")
            connected_query = """
            MATCH (v:Vulnerability)-[:EXPLOITS]->(w:Weakness)
            RETURN v.canonical_id AS vuln_id, w.cwe_id AS cwe_id, w.name AS weakness_name
            LIMIT 5
            """
            result = session.run(connected_query)

            found_connections = False
            for record in result:
                found_connections = True
                print(f"   {record['vuln_id']} → EXPLOITS → {record['cwe_id']} ({record['weakness_name']})")

            if not found_connections:
                print("   ⚠️  No EXPLOITS relationships found in graph")

            return True

    except Exception as e:
        print(f"❌ ERROR: Could not connect to Neo4j: {e}")
        print("\nTroubleshooting:")
        print("1. Check NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD in .env")
        print("2. Verify Neo4j Aura instance is running")
        print("3. Run: python scripts/init_neo4j_schema.py")
        return False


def check_postgresql_embeddings():
    """
    Test 2: Check if PostgreSQL has embeddings populated.
    """
    print_section("TEST 2: PostgreSQL Embeddings Status")

    conn = get_db_connection()
    if conn is None:
        print("❌ ERROR: Could not connect to PostgreSQL")
        return False

    try:
        cursor = conn.cursor()

        # Check total records
        cursor.execute("SELECT COUNT(*) FROM threat_intelligence_records")
        total_records = cursor.fetchone()[0]
        print(f"\n📊 Total threat intelligence records: {total_records}")

        # Check embeddings
        cursor.execute("""
            SELECT COUNT(*) FROM threat_intelligence_records
            WHERE embedding IS NOT NULL
        """)
        embedded_records = cursor.fetchone()[0]
        print(f"📊 Records with embeddings: {embedded_records}")

        if embedded_records > 0:
            percentage = (embedded_records / total_records) * 100
            print(f"   ✅ {percentage:.1f}% of records have embeddings")
        else:
            print("   ⚠️  No embeddings found - vector search will not work")
            print("   Run ingestion pipeline to generate embeddings")

        # Sample records
        print("\n🔍 Sample Records (first 3):")
        cursor.execute("""
            SELECT canonical_id, package_name, source, severity,
                   LEFT(summary, 80) AS summary_snippet,
                   CASE WHEN embedding IS NOT NULL THEN 'YES' ELSE 'NO' END AS has_embedding
            FROM threat_intelligence_records
            LIMIT 3
        """)

        for row in cursor.fetchall():
            print(f"\n   ID: {row[0]}")
            print(f"   Package: {row[1]}")
            print(f"   Source: {row[2]}")
            print(f"   Severity: {row[3]}")
            print(f"   Summary: {row[4]}...")
            print(f"   Has Embedding: {row[5]}")

        return True

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False
    finally:
        release_db_connection(conn)


def test_retrieval_methods(query: str, package_name: str = "django"):
    """
    Test 3: Test each retrieval method individually and show what data is returned.

    Args:
        query: Search query (e.g., "SQL injection")
        package_name: Target package (e.g., "django")
    """
    print_section(f"TEST 3: Individual Retrieval Methods - Query: '{query}'")

    # Method 1: Vector Search
    print("\n🔹 Method 1: Semantic Vector Search (pgvector)")
    try:
        vector_results = semantic_vector_search(query, limit=3)
        if vector_results:
            print(f"   ✅ Found {len(vector_results)} results")
            for i, result in enumerate(vector_results, 1):
                print(f"\n   Result {i}:")
                print(f"      ID: {result.get('canonical_id')}")
                print(f"      Similarity: {result.get('similarity', 0):.4f}")
                print(f"      Summary: {result.get('summary', '')[:100]}...")
        else:
            print("   ⚠️  No results (embeddings may not be populated)")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")

    # Method 2: Full-text Search
    print("\n🔹 Method 2: Full-Text Search (PostgreSQL tsvector)")
    try:
        text_results = fetch_semantic_cti_data(query)
        print(f"   Results:\n{text_results[:500]}...")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")

    # Method 3: Graph Traversal
    print("\n🔹 Method 3: Graph Traversal Search (Neo4j)")

    # First, find a seed entity to traverse from
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT canonical_id FROM threat_intelligence_records
                WHERE to_tsvector('english', summary) @@ plainto_tsquery('english', %s)
                LIMIT 1
            """, (query,))

            seed_row = cursor.fetchone()
            if seed_row:
                seed_id = seed_row[0]
                print(f"   Using seed entity: {seed_id}")

                graph_results = graph_traversal_search(seed_id, max_hops=2)
                if graph_results:
                    print(f"   ✅ Found {len(graph_results)} connected entities")
                    for i, result in enumerate(graph_results[:3], 1):
                        print(f"\n   Connected Entity {i}:")
                        print(f"      Type: {result.get('node_type')}")
                        print(f"      ID: {result.get('canonical_id')}")
                        print(f"      Summary: {result.get('summary', 'N/A')[:80]}...")
                else:
                    print("   ⚠️  No graph connections found")
            else:
                print("   ⚠️  No seed entity found for graph traversal")

        except Exception as e:
            print(f"   ❌ ERROR: {e}")
        finally:
            release_db_connection(conn)


def test_hybrid_retrieval(query: str, package_name: str = "django"):
    """
    Test 4: Test the complete hybrid retrieval that combines all methods.
    This is what the researcher_node actually uses.
    """
    print_section(f"TEST 4: Hybrid Retrieval (What Researcher Agent Receives)")

    print(f"\nQuery: '{query}'")
    print(f"Package: '{package_name}'")

    try:
        # This is the exact function called by researcher_node in graph_agents.py
        hybrid_results = hybrid_retrieval(query, package_name)

        print("\n📦 HYBRID RETRIEVAL OUTPUT (sent to analyzer agent):")
        print("-" * 80)
        print(hybrid_results)
        print("-" * 80)

        # Parse and analyze the results
        lines = hybrid_results.split('\n')
        entity_count = len([l for l in lines if l.strip().startswith('[')])

        print(f"\n✅ Retrieved {entity_count} unique entities")

        # Count by retrieval method
        vector_count = len([l for l in lines if '[vector_search]' in l])
        fulltext_count = len([l for l in lines if '[fulltext]' in l])
        graph_count = len([l for l in lines if '[graph_traversal]' in l])

        print(f"\n📊 Breakdown by Method:")
        print(f"   Vector Search: {vector_count}")
        print(f"   Full-text Search: {fulltext_count}")
        print(f"   Graph Traversal: {graph_count}")

        # Show sample URLs
        print(f"\n🔗 Sample Source URLs (first 3):")
        url_lines = [l for l in lines if 'Source:' in l][:3]
        for line in url_lines:
            url_part = line.split('Source:')[1].split('|')[0].strip()
            print(f"   {url_part}")

        return hybrid_results

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_complete_flow(query: str):
    """
    Test 5: Simulate the complete user query flow through LangGraph.
    Shows what the analyzer agent receives and generates.
    """
    print_section(f"TEST 5: Complete User Query Flow Simulation")

    print(f"\nUser Query: '{query}'")
    print("\nThis simulates: User Query → Researcher Node → Analyzer Node → Response")

    try:
        from langchain_aws import ChatBedrock

        # Initialize the same LLM used in production
        llm = ChatBedrock(
            model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            model_kwargs={
                "temperature": 0.3,
                "max_tokens": 2048
            }
        )

        print("\n📡 Step 1: Researcher Node - Retrieving context from GraphRAG...")

        # Get the hybrid retrieval results (what researcher_node returns)
        context = hybrid_retrieval(query, package_name=query)

        print(f"   ✅ Retrieved {len(context)} characters of context")

        print("\n📡 Step 2: Analyzer Node - Generating threat report...")

        # Simulate what analyzer_node does
        analyzer_prompt = """You are an expert Cyber Threat Intelligence Analyst.
        Evaluate the provided security records.

        Task:
        1. You must isolate and include the exact source reference URLs provided in the raw context. Do not invent links.
        2. For every vulnerability or threat pattern you find, you MUST explicitly include its authentic source reference URL exactly as provided in the context data.
        3. Generate a concise answer grounded only by in the retrieved database context.
            Focus on:
            1. weakness being exploited
            2. the goal of the attackers
            3. the potential impact of the vulnerability
            4. defense controls that could mitigate the threat

        Format your response beautifully using Markdown headings, bullet points, and bold text so it displays cleanly in the UI."""

        from langchain_core.messages import SystemMessage, HumanMessage

        messages = [
            SystemMessage(content=analyzer_prompt),
            HumanMessage(content=f"Here is the database context found for this query:\n{context}")
        ]

        response = llm.invoke(messages)

        print("\n📄 ANALYZER RESPONSE (what user sees):")
        print("=" * 80)
        print(response.content)
        print("=" * 80)

        # Analyze the response
        print("\n📊 Response Analysis:")
        url_count = response.content.count('http')
        print(f"   URLs in response: {url_count}")

        cve_count = response.content.count('CVE-')
        print(f"   CVE mentions: {cve_count}")

        cwe_count = response.content.count('CWE-')
        print(f"   CWE mentions: {cwe_count}")

        return response.content

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None


def interactive_query_mode():
    """
    Test 6: Interactive mode where you can test different queries.
    """
    print_section("TEST 6: Interactive Query Mode")

    print("\nEnter queries to test the knowledge graph retrieval.")
    print("Type 'quit' to exit.\n")

    while True:
        query = input("Query: ").strip()

        if query.lower() in ['quit', 'exit', 'q']:
            print("\nExiting interactive mode...")
            break

        if not query:
            continue

        print("\n" + "-" * 80)

        # Quick test of hybrid retrieval
        try:
            results = hybrid_retrieval(query, package_name=query)
            print(f"\n📦 Hybrid Retrieval Results:\n")
            print(results[:800])  # Show first 800 chars

            if len(results) > 800:
                print(f"\n... (truncated, total {len(results)} characters)")
        except Exception as e:
            print(f"❌ ERROR: {e}")

        print("\n" + "-" * 80)


def main():
    """
    Main test runner - executes all tests in sequence.
    """
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║         Knowledge Graph Retrieval Testing Suite                           ║
║                                                                            ║
║  This script tests the complete GraphRAG pipeline:                        ║
║  1. Neo4j graph data inspection                                           ║
║  2. PostgreSQL embeddings verification                                    ║
║  3. Individual retrieval methods                                          ║
║  4. Hybrid retrieval (what analyzer receives)                             ║
║  5. Complete user query flow simulation                                   ║
║  6. Interactive query mode                                                ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)

    # Test 1: Check Neo4j data
    neo4j_ok = check_neo4j_data()

    if not neo4j_ok:
        print("\n⚠️  Neo4j connection failed. Some tests will be skipped.")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            return

    # Test 2: Check PostgreSQL embeddings
    check_postgresql_embeddings()

    # Test 3: Individual retrieval methods
    test_query = input("\nEnter a test query (or press Enter for 'SQL injection'): ").strip()
    if not test_query:
        test_query = "SQL injection"

    test_retrieval_methods(test_query)

    # Test 4: Hybrid retrieval
    test_hybrid_retrieval(test_query)

    # Test 5: Complete flow (optional - requires LLM call)
    print("\n" + "=" * 80)
    response = input("\nTest complete user query flow with LLM? (y/n): ")
    if response.lower() == 'y':
        test_complete_flow(test_query)

    # Test 6: Interactive mode
    print("\n" + "=" * 80)
    response = input("\nEnter interactive query mode? (y/n): ")
    if response.lower() == 'y':
        interactive_query_mode()

    print("\n✅ Testing complete!")
    print("\nNext steps:")
    print("1. If Neo4j is empty, run: python test/run_worker.py")
    print("2. If embeddings are missing, run: python scripts/ingest_to_sqs.py")
    print("3. To test the UI: streamlit run app_dashboard.py")


if __name__ == "__main__":
    main()
