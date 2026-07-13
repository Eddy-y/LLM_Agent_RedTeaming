"""
Test enhanced relationship extraction prompts with concrete examples.
Run this BEFORE deploying to Lambda to verify agents extract relationships.
"""

import sys
import os
import json

# Add src to path for Lambda-style imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Mock AWS config for local testing
os.environ['AWS_REGION'] = os.getenv('AWS_REGION', 'us-east-1')
os.environ['AWS_PROFILE_NAME'] = os.getenv('AWS_PROFILE_NAME', 'default')

from agents import run_nvd_agent
from graph_extractor import extract_graph_entities, validate_relationship_triple

# Sample CVE with explicit CWE in weaknesses field
sample_nvd_data = {
    "cve": {
        "id": "CVE-2024-TEST-RELATIONSHIPS",
        "descriptions": [{
            "lang": "en",
            "value": "SQL injection vulnerability in Flask application allows remote code execution."
        }],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseSeverity": "CRITICAL",
                    "baseScore": 9.8
                }
            }]
        },
        "published": "2024-01-15T10:30:00.000",
        "references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-TEST-RELATIONSHIPS"}
        ],
        "weaknesses": [{
            "description": [{"lang": "en", "value": "CWE-89"}]
        }]
    }
}

print("="*80)
print("TESTING ENHANCED NVD AGENT WITH RELATIONSHIP EXAMPLES")
print("="*80)
print("\nInput CVE data:")
print(f"  - CVE ID: CVE-2024-TEST-RELATIONSHIPS")
print(f"  - Has CWE in weaknesses: YES (CWE-89)")
print(f"  - Target package: flask")

try:
    print("\n" + "-"*80)
    print("Calling run_nvd_agent...")
    print("-"*80)

    result = run_nvd_agent([sample_nvd_data], "flask")

    if not result:
        print("❌ FAILED: Agent returned None or empty list")
        sys.exit(1)

    print(f"\n✅ Agent returned {len(result)} items")

    for i, item in enumerate(result, 1):
        print(f"\n{'='*80}")
        print(f"ITEM {i}")
        print(f"{'='*80}")

        print(f"\nID: {item.get('id', 'MISSING')}")
        print(f"Details: {item.get('details', 'MISSING')[:80]}...")
        print(f"Severity: {item.get('severity', 'MISSING')}")

        print(f"\nKeys in result: {sorted(item.keys())}")

        if 'relationships' not in item:
            print("\n❌ CRITICAL FAILURE: 'relationships' key is MISSING!")
            print("   The LLM is still not returning the relationships field.")
            print("   This means the prompt needs MORE explicit instruction.")
            continue

        relationships = item.get('relationships', [])

        if not relationships:
            print("\n⚠️  WARNING: 'relationships' field exists but is EMPTY")
            print("   The LLM understands the schema but didn't extract relationships.")
            print("   Check if the input data actually contains extractable relationships.")
        else:
            print(f"\n✅ SUCCESS: Found {len(relationships)} relationships!")

            for j, rel in enumerate(relationships, 1):
                print(f"\n  Relationship {j}:")
                print(f"    Subject: {rel.get('subject')} ({rel.get('subject_type')})")
                print(f"    Predicate: {rel.get('predicate')}")
                print(f"    Object: {rel.get('object')} ({rel.get('object_type')})")

                # Validate the relationship
                is_valid = validate_relationship_triple(rel)
                if is_valid:
                    print(f"    ✅ Validation: PASSED")
                else:
                    print(f"    ❌ Validation: FAILED (will be rejected by graph_extractor)")

    # Test graph extraction pipeline
    print(f"\n{'='*80}")
    print("TESTING GRAPH EXTRACTION PIPELINE")
    print(f"{'='*80}")

    # Extract all relationships from all items
    all_relationships = []
    for item in result:
        if 'relationships' in item:
            all_relationships.extend(item.get('relationships', []))

    print(f"\nTotal relationships to process: {len(all_relationships)}")

    # Mock normalized_data (would come from central normalizer in real pipeline)
    normalized_data = [{
        "canonical_id": item.get('id'),
        "record_type": "CVE",
        "title": item.get('details', '')[:100],
        "summary": item.get('details', ''),
        "severity": item.get('severity'),
        "published_at": item.get('published_at'),
        "source": "nvd"
    } for item in result]

    # Run graph extractor
    graph_data = extract_graph_entities(normalized_data, all_relationships)

    print(f"\nGraph Extraction Results:")
    print(f"  Nodes created: {len(graph_data['nodes'])}")
    print(f"  Edges created: {len(graph_data['relationships'])}")

    if graph_data['relationships']:
        print(f"\n✅ SUCCESS: Graph extractor created {len(graph_data['relationships'])} edges!")
        print("\nSample edges:")
        for edge in graph_data['relationships'][:3]:
            print(f"  - {edge['from_node']['id_value']} -{edge['type']}-> {edge['to_node']['id_value']}")
    else:
        print("\n❌ FAILURE: Graph extractor created 0 edges")
        print("   All relationships were rejected during validation")

    print(f"\n{'='*80}")
    print("DIAGNOSIS")
    print(f"{'='*80}")

    if graph_data['relationships']:
        print("\n✅ READY TO DEPLOY!")
        print("   The enhanced prompts are working correctly.")
        print("   Next step: Deploy to Lambda with 'sam build && sam deploy'")
    else:
        print("\n❌ NOT READY")
        print("   The agent needs further prompt improvements.")
        print("   The relationships field exists but relationships are invalid.")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
