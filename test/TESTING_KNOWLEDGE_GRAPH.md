# Testing Knowledge Graph Retrieval - Complete Guide

This guide helps you verify that your Neo4j knowledge graph integration is working correctly and understand what information flows through your GraphRAG system.

## Quick Start - Is Everything Working?

Run this first to get a status overview:

```bash
python test/check_graph_status.py
```

This will tell you:
- ✅ If Neo4j is connected and has data
- ✅ If PostgreSQL embeddings are populated
- ✅ If hybrid retrieval is working
- ⚠️ What needs fixing if something is broken

---

## Test Suite Overview

We have multiple testing scripts for different purposes:

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `check_graph_status.py` | Quick health check | First thing to run |
| `test_graphrag.py` | Full GraphRAG integration tests | Verify all components work |
| `test_knowledge_graph_retrieval.py` | Interactive testing with LLM | See what analyzer agent receives |

---

## Part 1: Verify Neo4j Has Data

### Check if Neo4j is populated

```bash
# Method 1: Python test
python -c "from src.graph_db import get_neo4j_session; \
with get_neo4j_session() as s: \
    r = s.run('MATCH (n) RETURN count(n) AS total'); \
    print(f'Nodes: {r.single()[\"total\"]}')"
```

### Check what types of nodes exist

```python
# Run in Python REPL or Jupyter
from src.graph_db import get_neo4j_session

with get_neo4j_session() as session:
    result = session.run("""
        MATCH (n)
        RETURN labels(n)[0] AS node_type, COUNT(n) AS count
        ORDER BY count DESC
    """)
    
    for record in result:
        print(f"{record['node_type']}: {record['count']} nodes")
```

Expected output (if populated):
```
Vulnerability: 150 nodes
Weakness: 30 nodes
Package: 25 nodes
AttackTactic: 10 nodes
```

### Check relationships

```python
with get_neo4j_session() as session:
    result = session.run("""
        MATCH ()-[r]->()
        RETURN type(r) AS rel_type, COUNT(r) AS count
        ORDER BY count DESC
    """)
    
    for record in result:
        print(f"{record['rel_type']}: {record['count']} relationships")
```

Expected output:
```
EXPLOITS: 120 relationships
AFFECTS: 80 relationships
ENABLES: 45 relationships
```

---

## Part 2: Test Individual Retrieval Methods

### Method 1: Vector Search (Semantic Similarity)

```python
from graph_agents import semantic_vector_search

results = semantic_vector_search("SQL injection vulnerability", limit=5)

for r in results:
    print(f"ID: {r['canonical_id']}")
    print(f"Similarity: {r['similarity']:.4f}")
    print(f"Summary: {r['summary'][:80]}...")
    print()
```

**What this tests:**
- ✅ Bedrock Titan embeddings are working
- ✅ pgvector extension is installed
- ✅ Embeddings are populated in PostgreSQL

**If it fails:**
- Check `embedding` column in `threat_intelligence_records` table
- Run ingestion pipeline to generate embeddings
- Verify Bedrock credentials in `.env`

### Method 2: Full-Text Search

```python
from graph_agents import fetch_semantic_cti_data

results = fetch_semantic_cti_data("Django authentication")
print(results)
```

**What this tests:**
- ✅ PostgreSQL full-text search indexes are working
- ✅ Basic database connectivity

### Method 3: Graph Traversal

```python
from graph_agents import graph_traversal_search

# Use a real CVE from your database
results = graph_traversal_search("CVE-2024-12345", max_hops=2)

for r in results:
    print(f"Type: {r['node_type']}")
    print(f"ID: {r['canonical_id']}")
    print(f"Summary: {r.get('summary', 'N/A')[:60]}...")
    print()
```

**What this tests:**
- ✅ Neo4j connectivity
- ✅ Graph relationships are created correctly
- ✅ Multi-hop traversal logic works

**If it fails:**
- Check Neo4j credentials in `.env`
- Verify relationships exist: Run Cypher query `MATCH ()-[r]->() RETURN count(r)`
- Check if graph extractor is creating relationships during ingestion

---

## Part 3: Test Hybrid Retrieval (What Analyzer Receives)

This is **the most important test** - it shows exactly what context the analyzer agent receives.

```python
from graph_agents import hybrid_retrieval

# This is what researcher_node calls internally
context = hybrid_retrieval("SQL injection", package_name="django")

print(context)
```

**Example output:**
```
Hybrid Search Results (8 unique entities):

[vector_search] ID: CVE-2024-1234 | Source: https://nvd.nist.gov/vuln/detail/CVE-2024-1234 | Summary: SQL injection in Django ORM allows...
[graph_traversal] ID: CWE-89 | Source: https://cwe.mitre.org/data/definitions/89.html | Summary: Improper neutralization of SQL commands...
[vector_search] ID: GHSA-xxx-yyy | Source: https://github.com/advisories/GHSA-xxx-yyy | Summary: Django authentication bypass via...
```

**What to check:**
1. **Number of entities**: Should have 5-15 results (not 0, not 100)
2. **Retrieval methods**: Should see mix of `[vector_search]`, `[fulltext]`, `[graph_traversal]`
3. **URLs**: Should be programmatically constructed (nvd.nist.gov, github.com, pypi.org)
4. **Deduplication**: Should not see duplicate canonical_ids

**Red flags:**
- ❌ Empty results → Database is empty or query doesn't match data
- ❌ Only `[fulltext]` → Embeddings not populated or Neo4j empty
- ❌ No `[graph_traversal]` → Neo4j has no relationships
- ❌ Fabricated URLs → URL construction logic is broken

---

## Part 4: Test Complete User Query Flow

This simulates the entire LangGraph execution: `User Query → Researcher → Analyzer → Response`

```bash
python test/test_knowledge_graph_retrieval.py
```

This script will:
1. Check Neo4j data status
2. Check PostgreSQL embeddings
3. Test each retrieval method individually
4. Show what hybrid retrieval returns
5. **Simulate complete LLM flow** (requires Bedrock call)
6. Interactive query mode

### What the Interactive Test Shows

When you run test 5 (complete flow), you'll see:

```
📡 Step 1: Researcher Node - Retrieving context from GraphRAG...
   ✅ Retrieved 2847 characters of context

📡 Step 2: Analyzer Node - Generating threat report...

📄 ANALYZER RESPONSE (what user sees):
================================================================================
## SQL Injection Vulnerabilities in Django

### Weakness Being Exploited
The vulnerabilities exploit **CWE-89: SQL Injection**, where user-supplied...

### Attacker Goals
- Execute arbitrary SQL queries to extract sensitive data
- Bypass authentication mechanisms
- Modify or delete database records

### Source References
- https://nvd.nist.gov/vuln/detail/CVE-2024-1234
- https://github.com/advisories/GHSA-xxx-yyy
================================================================================

📊 Response Analysis:
   URLs in response: 3
   CVE mentions: 2
   CWE mentions: 1
```

**What to verify:**
- ✅ URLs match the ones from hybrid retrieval
- ✅ No hallucinated CVE-* or URL patterns
- ✅ Response is grounded in retrieved context
- ✅ Markdown formatting is clean

---

## Part 5: Verify URL Validation

After the analyzer runs, check the `url_validation_logs` table:

```sql
SELECT 
    agent_name,
    file_origin,
    hallucination_detected,
    url_validation_json->>'valid_urls' AS valid_urls,
    url_validation_json->>'invalid_urls' AS invalid_urls
FROM url_validation_logs
WHERE agent_name = 'Analyzer Agent'
ORDER BY timestamp DESC
LIMIT 1;
```

**What to check:**
- ✅ `hallucination_detected = false`
- ✅ All URLs in response are in `valid_urls` array
- ✅ No 404s or broken links

---

## Part 6: Check What Graph Data Exists

### View sample vulnerabilities with their connections

```python
from src.graph_db import get_neo4j_session

with get_neo4j_session() as session:
    result = session.run("""
        MATCH (v:Vulnerability)-[r]->(target)
        RETURN v.canonical_id AS vuln,
               type(r) AS relationship,
               labels(target)[0] AS target_type,
               COALESCE(target.cwe_id, target.name) AS target_id
        LIMIT 10
    """)
    
    for record in result:
        print(f"{record['vuln']} --[{record['relationship']}]--> {record['target_type']}:{record['target_id']}")
```

**Example output:**
```
CVE-2024-1234 --[EXPLOITS]--> Weakness:CWE-89
CVE-2024-1234 --[AFFECTS]--> Package:django
CVE-2024-5678 --[ENABLES]--> AttackTactic:T1190
```

---

## Part 7: Debug Graph Traversal

If graph traversal returns no results, check this:

```python
from src.graph_db import get_neo4j_session

# Check if a specific vulnerability has outgoing relationships
with get_neo4j_session() as session:
    result = session.run("""
        MATCH (v:Vulnerability {canonical_id: $cve_id})-[r]->(n)
        RETURN type(r) AS rel_type, labels(n)[0] AS target_type, count(*) AS count
    """, cve_id="CVE-2024-1234")  # Replace with real CVE
    
    for record in result:
        print(f"{record['rel_type']} → {record['target_type']}: {record['count']}")
```

**If empty:**
- ❌ Graph extractor is not creating relationships
- ❌ Check `normalized_record['relationships']` field during ingestion
- ❌ Verify agents are returning relationship triples

---

## Troubleshooting Common Issues

### Issue 1: "No results from hybrid retrieval"

**Diagnosis:**
```bash
python test/check_graph_status.py
```

Look for:
- Total records: 0 → Run ingestion: `python scripts/ingest_to_sqs.py`
- Embeddings: 0 → Embeddings not generated during ingestion
- Neo4j nodes: 0 → Graph extractor not running or failing

**Fix:**
```bash
# Re-run complete pipeline
python scripts/ingest_to_sqs.py
python test/run_worker.py
```

### Issue 2: "Vector search returns nothing"

**Diagnosis:**
```sql
SELECT COUNT(*) FROM threat_intelligence_records WHERE embedding IS NOT NULL;
```

If result is 0:

**Fix:**
```python
# Manually generate embeddings for existing records
from src.db import get_db_connection, release_db_connection
from src.embeddings import generate_embedding

conn = get_db_connection()
cursor = conn.cursor()

cursor.execute("SELECT id, summary FROM threat_intelligence_records WHERE embedding IS NULL LIMIT 100")

for row in cursor.fetchall():
    record_id, summary = row
    embedding = generate_embedding(summary)
    
    cursor.execute(
        "UPDATE threat_intelligence_records SET embedding = %s WHERE id = %s",
        (embedding, record_id)
    )

conn.commit()
release_db_connection(conn)
```

### Issue 3: "Graph traversal returns nothing"

**Diagnosis:**
```cypher
// Run in Neo4j Browser or Python
MATCH ()-[r]->() RETURN count(r) AS total_relationships
```

If result is 0:

**Fix:**
1. Check agent output in `src/agents.py` - do they return `relationships` field?
2. Check `src/graph_extractor.py` - is `extract_triples()` validating correctly?
3. Check `src/lambda_worker.py` - is `batch_insert_graph()` being called?

### Issue 4: "ModuleNotFoundError: No module named 'neo4j'"

**Fix:**
```bash
pip install -r cti_dependencies/requirements-full.txt
```

Or specifically:
```bash
pip install neo4j>=5.14.0
```

---

## What Good Output Looks Like

### Successful Hybrid Retrieval
```
Hybrid Search Results (12 unique entities):

[vector_search] ID: CVE-2024-1234 | Source: https://nvd.nist.gov/vuln/detail/CVE-2024-1234 | Summary: SQL injection in Django...
[vector_search] ID: CVE-2023-5678 | Source: https://nvd.nist.gov/vuln/detail/CVE-2023-5678 | Summary: Authentication bypass...
[graph_traversal] ID: CWE-89 | Source: https://cwe.mitre.org/data/definitions/89.html | Summary: SQL Injection weakness...
[graph_traversal] ID: CVE-2024-9999 | Source: https://nvd.nist.gov/vuln/detail/CVE-2024-9999 | Summary: Related SQL injection...
```

**Key indicators:**
- ✅ Mix of retrieval methods (vector, fulltext, graph)
- ✅ URLs are real and valid
- ✅ No duplicate IDs
- ✅ 5-20 entities returned

### Successful Analyzer Response
```markdown
## SQL Injection in Django

### Weaknesses Exploited
- **CWE-89**: SQL Injection
- **CWE-79**: Cross-Site Scripting

### Attacker Goals
- Extract sensitive data from database
- Bypass authentication

### Source References
- https://nvd.nist.gov/vuln/detail/CVE-2024-1234
- https://github.com/advisories/GHSA-xxx-yyy
```

**Key indicators:**
- ✅ URLs match hybrid retrieval output
- ✅ No fabricated CVE/CWE IDs
- ✅ Grounded in retrieved context
- ✅ Markdown formatting works

---

## Next Steps After Testing

Once all tests pass:

1. **Test via API**:
   ```bash
   python -m uvicorn api:app --reload
   curl http://localhost:8000/generate_report_stream?package=django
   ```

2. **Test via Dashboard**:
   ```bash
   streamlit run app_dashboard.py
   ```

3. **Check Metrics**:
   ```sql
   SELECT * FROM graph_execution_metrics ORDER BY evaluated_at DESC LIMIT 5;
   ```

4. **Monitor URL Validation**:
   ```sql
   SELECT hallucination_detected, COUNT(*) 
   FROM url_validation_logs 
   GROUP BY hallucination_detected;
   ```

---

## Key Files for Debugging

| File | Purpose |
|------|---------|
| `graph_agents.py:106-164` | `hybrid_retrieval()` - Main retrieval function |
| `graph_agents.py:62-103` | `graph_traversal_search()` - Neo4j queries |
| `graph_agents.py:21-59` | `semantic_vector_search()` - Vector similarity |
| `src/graph_extractor.py` | Extracts entities/relationships from agent output |
| `src/graph_db.py` | Neo4j connection and batch insert |
| `src/embeddings.py` | Bedrock Titan embedding generation |

---

## Summary Checklist

Before claiming "GraphRAG is working", verify:

- [ ] Neo4j has nodes (>0)
- [ ] Neo4j has relationships (>0)
- [ ] PostgreSQL has records (>0)
- [ ] PostgreSQL embeddings populated (>0)
- [ ] Vector search returns results
- [ ] Graph traversal returns results
- [ ] Hybrid retrieval combines all methods
- [ ] Analyzer receives proper context
- [ ] Analyzer response has valid URLs
- [ ] No hallucinated CVE/CWE IDs
- [ ] URL validation shows no broken links

Run:
```bash
python test/check_graph_status.py           # Quick check
python test/test_graphrag.py                # Full integration tests
python test/test_knowledge_graph_retrieval.py  # Interactive with LLM
```

---

## Additional Resources

- **Neo4j Browser**: https://workspace.neo4j.io/workspace/query
  - Run Cypher queries directly
  - Visualize graph structure

- **PostgreSQL Client**:
  ```bash
  psql -h $DB_HOST -U $DB_USER -d $DB_NAME
  ```

- **AWS Bedrock Console**: Monitor embedding generation costs
- **CloudWatch Logs**: Check Lambda worker execution logs
