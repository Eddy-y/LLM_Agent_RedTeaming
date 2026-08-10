"""Test Neo4j write directly to diagnose connection issues."""

from src.graph_db import get_neo4j_session, insert_graph_batch
from src.graph_extractor import extract_graph_entities

# Sample normalized record
normalized_records = [{
    'source': 'exploitdb',
    'record_type': 'EDB',
    'canonical_id': 'EDB-99999',  # Test ID
    'title': 'Test Exploit',
    'summary': 'Test exploit for Neo4j connection',
    'severity': 'HIGH',
    'published_at': '2020-01-01T00:00:00Z',
    'references': ['https://www.exploit-db.com/exploits/99999']
}]

relationships = []

print("=" * 80)
print("Testing Neo4j Write")
print("=" * 80)

# Extract graph data
graph_data = extract_graph_entities(normalized_records, relationships)
print(f"\nGraph data prepared:")
print(f"  Nodes: {len(graph_data.get('nodes', []))}")
print(f"  Relationships: {len(graph_data.get('relationships', []))}")

# Try to write to Neo4j
print("\nAttempting to write to Neo4j...")
try:
    with get_neo4j_session() as session:
        result = session.execute_write(insert_graph_batch, graph_data)
        print(f"\nSUCCESS!")
        print(f"  Nodes created: {result['nodes_created']}")
        print(f"  Relationships created: {result['relationships_created']}")

        # Verify it's there
        verify_result = session.run("MATCH (e:Exploit {edb_id: 'EDB-99999'}) RETURN e.title")
        record = verify_result.single()
        if record:
            print(f"\n Verified: Found test exploit with title: {record['e.title']}")

        # Clean up test data
        session.run("MATCH (e:Exploit {edb_id: 'EDB-99999'}) DETACH DELETE e")
        print("\n Cleaned up test data")

except Exception as e:
    print(f"\nERROR: Neo4j write failed!")
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {e}")

    import traceback
    print("\nFull traceback:")
    traceback.print_exc()
