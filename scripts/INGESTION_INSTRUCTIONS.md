# Step 2: Database Cleanup & Re-ingestion Instructions

## Overview
This guide walks you through cleaning your databases and re-ingesting data with proper embeddings and per-package pagination.

---

## Step 2.1: Clean PostgreSQL Database

Run the cleanup script:

```bash
cd /c/Users/eduar/Documents/TAMUSA/RESEARCH/LLM_Agent_RedTeaming
python scripts/cleanup_databases.py
```

**What it does:**
- Shows current record counts
- Asks for confirmation (type 'yes')
- Truncates all threat intelligence tables
- Resets all pagination offsets to 0
- Verifies cleanup was successful

**Expected output:**
```
Current record counts:
  - threat_intelligence_records: XXXX
  - url_validation_logs: XXXX
  ...

Are you sure you want to DELETE all this data? (type 'yes' to confirm): yes

[OK] Truncated threat_intelligence_records
[OK] Truncated url_validation_logs
...
[SUCCESS] PostgreSQL database cleaned successfully!
```

---

## Step 2.2: Clean Neo4j Graph Database

The script will print these commands for you to run manually:

1. Open **Neo4j Browser** or **Neo4j Desktop**
2. Connect to your **Neo4j Aura** instance
3. Run these Cypher queries:

```cypher
// Delete all nodes and relationships
MATCH (n) DETACH DELETE n;

// Verify cleanup (should return 0)
MATCH (n) RETURN count(n);
```

**Expected result:** Count should be **0**

---

## Step 2.3: Run Batch Ingestion

After both databases are cleaned, start the batch ingestion:

```bash
cd scripts

# Run 50 ingestion cycles (recommended)
python batch_ingestion.py --runs 50

# Or customize:
python batch_ingestion.py --runs 100 --pause 15
```

**Parameters:**
- `--runs`: Number of ingestion cycles (default: 50)
- `--pause`: Seconds to pause between runs (default: 10)

**What happens during ingestion:**
- Each run fetches:
  - 5 MITRE ATT&CK objects
  - 5 CAPEC attack patterns
  - ~20 NVD CVEs per package (numpy, flask)
  - ~20 GitHub advisories per package
- After each run, shows:
  - Record counts by source
  - Pagination offsets (should increase)
  - Embedding coverage
  - Time estimates

**Expected duration:**
- 50 runs × ~20 seconds per run = **~17 minutes**
- Progress displayed after each run
- Can interrupt with Ctrl+C (graceful exit)

---

## Step 2.4: Monitor Progress

### During Ingestion

The script shows real-time progress:

```
==================================================================
RUN 1/50 - 2026-07-10 14:30:00
==================================================================

--- Processing Universal Corpora (MITRE & CAPEC) ---
[SQS] Queued 5 new MITRE objects
[STATE] Advanced MITRE offset by 5 (new offset: 5)
...

------------------------------------------------------------------
PROGRESS SUMMARY - Run 1/50
------------------------------------------------------------------

Record Counts by Source:
  attack               |     5 records
  capec                |     5 records
  nvd                  |    40 records
  github_advisories    |    30 records
  TOTAL                |    80 records

Pagination State:
  capec                | Universal       | offset=5
  github_advisories    | flask           | offset=1
  github_advisories    | numpy           | offset=1
  mitre                | Universal       | offset=5
  nvd                  | flask           | offset=20
  nvd                  | numpy           | offset=20

Embedding Population:
  attack               | 5/5 (100.0%)
  capec                | 5/5 (100.0%)
  github_advisories    | 30/30 (100.0%)
  nvd                  | 40/40 (100.0%)
  TOTAL                | 80/80 (100.0%)

Time Statistics:
  Elapsed: 25s (0.4 min)
  Avg per run: 25.0s
  Estimated remaining: 1225s (20.4 min)
------------------------------------------------------------------
```

### After Completion

```
==================================================================
BATCH INGESTION COMPLETE
==================================================================

Final Statistics:
  Successful runs: 50/50
  Failed runs: 0/50
  Total time: 1050s (17.5 min)

Final Record Counts:
  attack               |    250 records
  capec                |    250 records
  github_advisories    |    150 records
  nvd                  |   2000 records
  pypi                 |    100 records
  TOTAL                |   2750 records

Final Pagination State:
  capec                | Universal       | offset=250
  github_advisories    | flask           | offset=50
  github_advisories    | numpy           | offset=50
  mitre                | Universal       | offset=250
  nvd                  | flask           | offset=1000
  nvd                  | numpy           | offset=1000
```

---

## Step 2.5: Verify Results

### PostgreSQL Verification

```bash
python -c "
from src.db import get_db_connection, release_db_connection

conn = get_db_connection()
try:
    with conn.cursor() as cur:
        # Total records
        cur.execute('SELECT COUNT(*) FROM threat_intelligence_records')
        print(f'Total records: {cur.fetchone()[0]}')
        
        # Records with embeddings
        cur.execute('SELECT COUNT(*) FROM threat_intelligence_records WHERE embedding IS NOT NULL')
        print(f'Records with embeddings: {cur.fetchone()[0]}')
        
        # Check for duplicates
        cur.execute('''
            SELECT canonical_id, COUNT(*)
            FROM threat_intelligence_records
            GROUP BY canonical_id
            HAVING COUNT(*) > 1
        ''')
        dupes = cur.fetchall()
        print(f'Duplicate canonical_ids: {len(dupes)}')
finally:
    release_db_connection(conn)
"
```

**Expected:**
- Total records: ~2,500-3,000
- Records with embeddings: 100% (should match total)
- Duplicate canonical_ids: 0

### Neo4j Verification

Open Neo4j Browser and run:

```cypher
// Count nodes by type
MATCH (n)
RETURN labels(n)[0] as NodeType, count(n) as Count
ORDER BY Count DESC;

// Count relationships by type
MATCH ()-[r]->()
RETURN type(r) as RelType, count(r) as Count
ORDER BY Count DESC;

// Sample vulnerability with connections
MATCH (v:Vulnerability)-[r]->(target)
WHERE v.canonical_id STARTS WITH 'CVE-'
RETURN v.canonical_id, type(r), labels(target)[0]
LIMIT 20;
```

**Expected:**
- **Nodes:** Vulnerability (~2000), Package (~50), Weakness (~100), etc.
- **Relationships:** EXPLOITS (~500), AFFECTS (~1000), ENABLES (~200), etc.

---

## Troubleshooting

### If ingestion fails mid-batch:

The script gracefully handles interruptions. Simply re-run:

```bash
python batch_ingestion.py --runs 50
```

Pagination state ensures no duplicate processing!

### If offsets aren't advancing:

Check logs for errors. Common issues:
- API rate limiting (wait and retry)
- Network connectivity (check internet)
- Database connection (verify credentials)

### If embeddings are missing:

Check Lambda worker logs. Embeddings are generated during SQS processing, not during ingestion.

---

## Summary

✅ **Step 2.1:** Clean PostgreSQL → `python scripts/cleanup_databases.py`  
✅ **Step 2.2:** Clean Neo4j → Run Cypher delete commands  
✅ **Step 2.3:** Batch ingest → `python scripts/batch_ingestion.py --runs 50`  
✅ **Step 2.4:** Monitor progress → Automatic real-time updates  
✅ **Step 2.5:** Verify results → SQL + Cypher queries  

**You're now ready to start Step 2!** 🚀
