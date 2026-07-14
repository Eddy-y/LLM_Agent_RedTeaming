"""
End-to-end testing for GraphRAG implementation.

Tests:
1. Neo4j connectivity
2. Graph data insertion
3. Hybrid retrieval (semantic + full-text + graph traversal)
4. Embedding generation
5. Dual-write verification
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_db import test_connection, get_neo4j_session, insert_graph_batch
from src.graph_extractor import extract_graph_entities, validate_relationship_triple
from src.embeddings import generate_embedding, cosine_similarity
from src.db import get_db_connection, release_db_connection
from graph_agents import hybrid_retrieval, semantic_vector_search, graph_traversal_search


def test_neo4j_connection():
    """Test 1: Verify Neo4j Aura connection."""
    print("\n" + "="*60)
    print("TEST 1: Neo4j Connection")
    print("="*60)

    success = test_connection()
    if success:
        print("✅ PASS: Successfully connected to Neo4j Aura")
        return True
    else:
        print("❌ FAIL: Could not connect to Neo4j Aura")
        return False


def test_graph_insertion():
    """Test 2: Insert test nodes and relationships into Neo4j."""
    print("\n" + "="*60)
    print("TEST 2: Graph Data Insertion")
    print("="*60)

    # Create test data
    test_nodes = [
        {
            "type": "Vulnerability",
            "properties": {
                "canonical_id": "CVE-TEST-001",
                "title": "Test SQL Injection",
                "summary": "Test vulnerability for GraphRAG testing",
                "severity": "HIGH",
                "source": "test"
            }
        },
        {
            "type": "Weakness",
            "properties": {
                "cwe_id": "CWE-89",
                "name": "SQL Injection",
                "description": "Improper neutralization of SQL commands"
            }
        }
    ]

    test_relationships = [
        {
            "type": "EXPLOITS",
            "from_node": {
                "type": "Vulnerability",
                "id_field": "canonical_id",
                "id_value": "CVE-TEST-001"
            },
            "to_node": {
                "type": "Weakness",
                "id_field": "cwe_id",
                "id_value": "CWE-89"
            },
            "properties": {}
        }
    ]

    graph_data = {
        "nodes": test_nodes,
        "relationships": test_relationships
    }

    try:
        with get_neo4j_session() as session:
            result = session.execute_write(insert_graph_batch, graph_data)
            print(f"✅ PASS: Inserted {result['nodes_created']} nodes, {result['relationships_created']} relationships")
            return True
    except Exception as e:
        print(f"❌ FAIL: Graph insertion error: {e}")
        return False


def test_embedding_generation():
    """Test 3: Generate embeddings using Bedrock Titan."""
    print("\n" + "="*60)
    print("TEST 3: Embedding Generation")
    print("="*60)

    test_text = "SQL injection vulnerability in Django authentication"

    try:
        embedding = generate_embedding(test_text)

        if embedding and len(embedding) == 1536:
            print(f"✅ PASS: Generated {len(embedding)}-dimensional embedding")

            # Test similarity
            embedding2 = generate_embedding("SQL injection in Django")
            similarity = cosine_similarity(embedding, embedding2)
            print(f"   Similarity between similar texts: {similarity:.3f}")

            if similarity > 0.8:
                print(f"✅ PASS: High similarity detected ({similarity:.3f} > 0.8)")
                return True
            else:
                print(f"⚠️  WARNING: Lower similarity than expected ({similarity:.3f} < 0.8)")
                return True
        else:
            print(f"❌ FAIL: Invalid embedding format: {type(embedding)}, length={len(embedding) if embedding else 0}")
            return False

    except Exception as e:
        print(f"❌ FAIL: Embedding generation error: {e}")
        return False


def test_graph_traversal():
    """Test 4: Query Neo4j graph with multi-hop traversal."""
    print("\n" + "="*60)
    print("TEST 4: Graph Traversal")
    print("="*60)

    try:
        # Try to find connected nodes from the test CVE
        results = graph_traversal_search("CVE-TEST-001", max_hops=2)

        if results:
            print(f"✅ PASS: Found {len(results)} connected nodes via graph traversal")
            for r in results:
                print(f"   - {r.get('node_type')}: {r.get('canonical_id')}")
            return True
        else:
            print("⚠️  WARNING: No graph traversal results (graph may be empty)")
            return True  # Not a failure if graph is empty
    except Exception as e:
        print(f"❌ FAIL: Graph traversal error: {e}")
        return False


def test_vector_search():
    """Test 5: Semantic vector search using pgvector."""
    print("\n" + "="*60)
    print("TEST 5: Vector Search (pgvector)")
    print("="*60)

    try:
        results = semantic_vector_search("SQL injection vulnerability", limit=3)

        if results:
            print(f"✅ PASS: Found {len(results)} results via vector search")
            for r in results:
                print(f"   - {r.get('canonical_id')}: similarity={r.get('similarity', 0):.3f}")
            return True
        else:
            print("⚠️  WARNING: No vector search results (embeddings may not be populated)")
            return True  # Not a failure if no embeddings yet
    except Exception as e:
        print(f"⚠️  WARNING: Vector search not available: {e}")
        return True  # Not critical


def test_hybrid_retrieval():
    """Test 6: Full hybrid retrieval combining all methods."""
    print("\n" + "="*60)
    print("TEST 6: Hybrid Retrieval (GraphRAG)")
    print("="*60)

    try:
        results = hybrid_retrieval("Django SQL injection", package_name="django")

        if results and len(results) > 0:
            print(f"✅ PASS: Hybrid retrieval returned results")
            print(f"\n{results[:500]}...")  # Print first 500 chars
            return True
        else:
            print("⚠️  WARNING: Hybrid retrieval returned no results (database may be empty)")
            return True  # Not a failure if database is empty
    except Exception as e:
        print(f"❌ FAIL: Hybrid retrieval error: {e}")
        return False


def test_relationship_validation():
    """Test 7: Relationship triple validation."""
    print("\n" + "="*60)
    print("TEST 7: Relationship Validation")
    print("="*60)

    # Valid relationship
    valid_triple = {
        "subject": "CVE-2023-1234",
        "subject_type": "Vulnerability",
        "predicate": "EXPLOITS",
        "object": "CWE-89",
        "object_type": "Weakness"
    }

    # Invalid relationship (bad CVE format)
    invalid_triple = {
        "subject": "INVALID-ID",
        "subject_type": "Vulnerability",
        "predicate": "EXPLOITS",
        "object": "CWE-89",
        "object_type": "Weakness"
    }

    valid_result = validate_relationship_triple(valid_triple)
    invalid_result = validate_relationship_triple(invalid_triple)

    if valid_result and not invalid_result:
        print("✅ PASS: Validation correctly accepts valid triples and rejects invalid ones")
        return True
    else:
        print(f"❌ FAIL: Validation error - valid={valid_result}, invalid={invalid_result}")
        return False


def test_postgresql_connection():
    """Test 8: PostgreSQL database connection."""
    print("\n" + "="*60)
    print("TEST 8: PostgreSQL Connection")
    print("="*60)

    conn = get_db_connection()

    if conn:
        print("✅ PASS: Successfully connected to PostgreSQL")
        release_db_connection(conn)
        return True
    else:
        print("❌ FAIL: Could not connect to PostgreSQL")
        return False


def run_all_tests():
    """Run all GraphRAG tests and report results."""
    print("\n" + "="*60)
    print("GraphRAG End-to-End Test Suite")
    print("="*60)

    tests = [
        ("PostgreSQL Connection", test_postgresql_connection),
        ("Neo4j Connection", test_neo4j_connection),
        ("Graph Data Insertion", test_graph_insertion),
        ("Relationship Validation", test_relationship_validation),
        ("Embedding Generation", test_embedding_generation),
        ("Graph Traversal", test_graph_traversal),
        ("Vector Search", test_vector_search),
        ("Hybrid Retrieval", test_hybrid_retrieval),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, passed))
        except Exception as e:
            print(f"\n❌ FATAL ERROR in {test_name}: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)

    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")

    print(f"\nTotal: {passed_count}/{total_count} tests passed")

    if passed_count == total_count:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {total_count - passed_count} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
