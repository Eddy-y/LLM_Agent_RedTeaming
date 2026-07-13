"""
Test if agents are extracting relationships from raw data.
This helps diagnose why Neo4j has no relationships despite 600+ nodes.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.agents import run_nvd_agent, run_github_agent
import json

# Sample CVE with explicit CWE mention
sample_nvd_cve = {
    "cve": {
        "id": "CVE-2024-TEST-001",
        "descriptions": [{
            "lang": "en",
            "value": "SQL injection vulnerability (CWE-89) in Flask application allows remote code execution."
        }],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {"baseSeverity": "CRITICAL"}
            }]
        },
        "published": "2024-01-15T00:00:00.000",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-TEST-001"],
        "weaknesses": [{
            "description": [{"lang": "en", "value": "CWE-89"}]
        }]
    }
}

# Sample GitHub Advisory with CWE
sample_github_advisory = {
    "id": "GHSA-test-1234-5678",
    "summary": "SQL injection in Django ORM",
    "severity": "HIGH",
    "publishedAt": "2024-01-15T00:00:00Z",
    "identifiers": [
        {"type": "GHSA", "value": "GHSA-test-1234-5678"},
        {"type": "CVE", "value": "CVE-2024-TEST-002"},
        {"type": "CWE", "value": "CWE-89"}
    ],
    "references": ["https://github.com/advisories/GHSA-test-1234-5678"],
    "vulnerabilities": {
        "nodes": [{
            "package": {"name": "django"},
            "vulnerableVersionRange": ">=2.0,<3.0"
        }]
    }
}

print("="*80)
print("TESTING NVD AGENT RELATIONSHIP EXTRACTION")
print("="*80)

try:
    nvd_result = run_nvd_agent([sample_nvd_cve], "flask")

    if nvd_result:
        print(f"\n✅ Agent returned {len(nvd_result)} items\n")
        for item in nvd_result:
            print(f"Item ID: {item.get('id', 'NO ID')}")
            print(f"Keys in result: {list(item.keys())}")

            if "relationships" in item:
                if item["relationships"]:
                    print(f"✅ RELATIONSHIPS FOUND: {len(item['relationships'])} relationships")
                    for rel in item["relationships"]:
                        print(f"  - {rel.get('subject')} -{rel.get('predicate')}-> {rel.get('object')}")
                else:
                    print("⚠️  'relationships' field exists but is EMPTY")
            else:
                print("❌ NO 'relationships' field in agent output!")

            print()
    else:
        print("❌ Agent returned None/empty")
except Exception as e:
    print(f"❌ NVD Agent Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("TESTING GITHUB AGENT RELATIONSHIP EXTRACTION")
print("="*80)

try:
    github_result = run_github_agent([sample_github_advisory])

    if github_result:
        print(f"\n✅ Agent returned {len(github_result)} items\n")
        for item in github_result:
            print(f"Item ID: {item.get('id', 'NO ID')}")
            print(f"Keys in result: {list(item.keys())}")

            if "relationships" in item:
                if item["relationships"]:
                    print(f"✅ RELATIONSHIPS FOUND: {len(item['relationships'])} relationships")
                    for rel in item["relationships"]:
                        print(f"  - {rel.get('subject')} -{rel.get('predicate')}-> {rel.get('object')}")
                else:
                    print("⚠️  'relationships' field exists but is EMPTY")
            else:
                print("❌ NO 'relationships' field in agent output!")

            print()
    else:
        print("❌ Agent returned None/empty")
except Exception as e:
    print(f"❌ GitHub Agent Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("DIAGNOSIS")
print("="*80)
print("""
If you see:
- ❌ NO 'relationships' field → LLM isn't returning the field at all
- ⚠️  Empty relationships → LLM returns field but doesn't extract relationships
- ✅ RELATIONSHIPS FOUND → Working correctly (problem elsewhere)

Next steps based on diagnosis:
1. NO field → Strengthen agent prompts with explicit JSON schema
2. Empty array → Improve relationship extraction prompts with examples
3. Working → Check graph_db.py insertion logic
""")
