# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

An autonomous Cyber Threat Intelligence (CTI) platform that harvests security feeds, normalizes them via multi-agent LLM orchestration (AWS Bedrock), and provides real-time analytics with hallucination verification and adversarial guardrails. The architecture implements **GraphRAG** (Graph-based Retrieval Augmented Generation) combining semantic vector search, knowledge graphs, and LLM reasoning for contextual threat intelligence.

**Core Research Questions (RQ) addressed:**
- RQ2: Semantic search with zero-hallucination URL construction (hybrid retrieval: vectors + graph traversal)
- RQ3: Active interception guardrails for weaponization prevention
- RQ4: Red-team adversarial emulation testing

**Key Technologies:**
- **Storage:** PostgreSQL (pgvector for embeddings) + Neo4j Aura (knowledge graph)
- **Embeddings:** AWS Bedrock Titan Text Embeddings v1 (1536 dimensions)
- **Graph Database:** Neo4j 5.14+ with Cypher query language
- **LLM Orchestration:** LangGraph + AWS Bedrock (Llama 3 8B)

## Architecture

### Data Flow Pipeline (GraphRAG Architecture)
1. **Ingestion** (`scripts/ingest_to_sqs.py`) → Fetches from PyPI, NVD, GitHub Advisories, MITRE ATT&CK, CAPEC → Pushes to AWS SQS
2. **Queue** (AWS SQS) → Decouples ingestion from processing
3. **Worker** (`src/lambda_worker.py`) → Lambda drains queue → Routes to specialist agents → Normalizes → **Dual Write**:
   - **PostgreSQL RDS:** Structured records + vector embeddings (pgvector)
   - **Neo4j Aura:** Knowledge graph (nodes + relationships)
4. **Embedding Generation** (`src/embeddings.py`) → Bedrock Titan creates 1536-dim vectors from threat summaries
5. **Graph Extraction** (`src/graph_extractor.py`) → Extracts entities (Vulnerability, Package, Weakness, etc.) and relationships (EXPLOITS, AFFECTS, ENABLES)
6. **Hybrid Retrieval** (`graph_agents.py`) → Combines:
   - Vector similarity search (pgvector cosine distance)
   - Full-text search (PostgreSQL tsvector)
   - Graph traversal (Neo4j Cypher queries for attack chains)
7. **LangGraph Engine** (`graph_agents.py`) → Conversational intelligence with researcher → analyzer → interception nodes
8. **Validation** (`src/validators/`) → URL validation and summary verification modules

### Key Components

**Multi-Agent System** (`src/agents.py`)
- Source-specific specialists: PyPI, GitHub, NVD, MITRE, CAPEC agents
- Each agent now extracts **relationship triples** (subject, predicate, object) for knowledge graph construction
- Central normalizer unifies schema across all sources
- All agents use AWS Bedrock (Llama 3 8B by default)

**Graph Extraction Engine** (`src/graph_extractor.py`)
- `extract_triples()`: Parses agent-extracted relationships with validation
- `build_graph_data()`: Converts triples to Neo4j-compatible nodes and edges
- Hallucination prevention: Validates entity IDs match known patterns (CVE-*, CWE-*, GHSA-*)
- Supports 6 node types and 13 relationship types

**Embeddings Module** (`src/embeddings.py`)
- `generate_embedding()`: Creates 1536-dimensional vectors using AWS Bedrock Titan Text Embeddings v1
- Caching: Embeddings stored in PostgreSQL `embedding` column for reuse
- Cost: ~$0.0001 per 1000 tokens (summary embeddings typically 50-200 tokens)

**Neo4j Graph Database** (`src/graph_db.py`)
- Connection management with connection pooling and SSL (neo4j+s:// protocol)
- `batch_insert_graph()`: Efficient MERGE operations for nodes and relationships
- Platform-aware SSL certificates (Windows: certifi, Linux: system)
- Automatic fallback: Neo4j writes are non-blocking (PostgreSQL always succeeds even if Neo4j fails)

**PostgreSQL Database** (`src/db.py`)
- ThreadedConnectionPool (1-20 connections)
- Tables: `threat_intelligence_records`, `ingestion_logs`, `graph_execution_metrics`, `url_validation_logs`, `summary_verification_logs`
- **pgvector extension:** Stores 1536-dim embeddings for semantic search
- Full-text search indexes on `summary` column

**LangGraph Workflow** (`graph_agents.py`)
- `researcher_node`: **Hybrid retrieval** combining:
  - Vector similarity search (pgvector cosine distance)
  - Full-text search (PostgreSQL tsvector)
  - Graph traversal (Neo4j Cypher for related CVEs, attack patterns)
- `analyzer_node`: Generates threat reports with strict source URL preservation
- `interception_node`: Safety guardrail that blocks weaponization requests
- `build_attacker_graph()`: Red-team testing harness with jailbreak attempts

**URL Validation** (`src/validators/url_validator.py`)
- `validate_and_log_urls()`: Lightweight URL validation without LLM overhead
- Spawns background thread for async validation
- Extracts all URLs from agent responses using regex
- Validates each URL via HTTP HEAD requests (checks for 404/timeouts)
- Logs detailed findings to `url_validation_logs` table with:
  - All URLs found in response
  - Which URLs are valid (HTTP 2xx/3xx)
  - Which URLs are invalid (4xx/5xx or unreachable)
  - Summary statistics

**Summary Verification** (`src/validators/summary_verifier.py`)
- Validates LLM-generated summaries against original source content without using LLMs
- Three-stage pipeline: scrape → extract keywords → calculate similarity
- **Scrapers**:
  - **NVDScraper**: Web scraper with 6-second rate limiting, retry logic, and fallback CSS selectors for NVD CVE pages
  - **GitHubAdvisoryScraper**: Web scraper with 2-second rate limiting for GitHub Security Advisory pages (GHSA-*)
- **KeywordExtractor**: TF-IDF-based keyword extraction with security-domain stopwords
- **SimilarityAnalyzer**: Hybrid scoring using Jaccard coefficient (0.6 weight) + fuzzy token matching (0.4 weight)
- **VerificationOrchestrator**: Coordinates workflow, automatically selects appropriate scraper based on source, logs results to `summary_verification_logs` table
- Verdict thresholds: MATCH (≥0.4 combined score), MISMATCH (<0.4), UNVERIFIABLE (scrape failed)
- Short summary adjustment: Lower threshold to 0.3 for summaries <20 characters
- Zero cost per verification (vs. $0.001 for LLM-based verification)
- Performance: ~7-8 seconds per NVD record (includes mandatory rate limit), ~3-4 seconds per GitHub Advisory

## Development Commands

### Environment Setup
```bash
# Create .env file with required credentials (see README for full list)
# Key variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, SQS_QUEUE_URL
# Database: DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, DB_PORT
# Optional: GITHUB_TOKEN, NVD_API_KEY

# Initialize database schema (run once or after schema changes)
python -m scripts.init_cloud_db

# Initialize Neo4j graph schema (run once after creating Neo4j Aura instance)
python -m scripts.init_neo4j_schema
```

### Data Pipeline Operations

**Step 1: Ingest raw data to SQS queue**
```bash
python scripts/ingest_to_sqs.py
```
- Respects NVD API rate limits with 6-second cooling window
- Queues messages for: PyPI, GitHub Advisories, NVD CVEs, MITRE ATT&CK, CAPEC
- Stores raw payloads in `data/raw/<run_id>/`
- **Deduplication:** Pre-LLM filtering skips already-processed canonical_ids (CVE-*, GHSA-*, etc.) to save Bedrock compute and prevent redundant database overwrites
- PyPI metadata is always queued (no deduplication) to allow for updated package information

**Step 2: Process queue with worker**
```bash
# Local worker daemon (for development)
python test/run_worker.py

# Or deploy as Lambda (AWS SAM)
sam build
sam deploy --profile <your-aws-profile>
```
- Worker uses exponential backoff for Bedrock throttling (4s → 8s → 16s)
- Automatically exits after 3 consecutive empty polls
- Maximum 4 retries per message before DLQ routing

**Step 3: Start API backend**
```bash
# Activate virtual environment first
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Start FastAPI server
python -m uvicorn api:app --reload
```
- Endpoints: `/generate_report_stream`, `/api/v1/metrics`, `/api/v1/threats`, `/api/v1/audits`
- Streams LangGraph execution via Server-Sent Events

**Step 4: Launch dashboard**
```bash
streamlit run app_dashboard.py
```

**Step 5: Verify summaries (optional)**
```bash
# Verify 50 records from NVD
python -m src.validators.summary_verifier --batch-size 50 --source nvd

# Verify GitHub Advisories
python -m src.validators.summary_verifier --batch-size 50 --source github_advisories

# Verbose mode with keyword/score output
python -m src.validators.summary_verifier --batch-size 10 --verbose --source github_advisories
```

### Testing

```bash
# Test individual prompts offline
python test/offline_test.py

# Run worker with mock data
python test/test_worker.py

# Generate phase 1 benchmarks
python test/generate_phase1_benchmarks.py

# Test summary verification components
python -m test.test_summary_verifier

# Test GraphRAG components (embeddings, graph extraction, Neo4j)
python test/test_graphrag.py

# Test Neo4j connection and schema
python -c "from src.graph_db import test_connection; test_connection()"

# Test embedding generation
python -c "from src.embeddings import generate_embedding; e = generate_embedding('test'); print(f'Embedding dim: {len(e)}')"

# Test hybrid retrieval (requires data in PostgreSQL + Neo4j)
python -c "from graph_agents import hybrid_retrieval; results = hybrid_retrieval('SQL injection', 'django'); print(f'Found {len(results)} results')"
```

### AWS SAM Deployment
```bash
# Build Lambda layer with dependencies
sam build

# Deploy stack (creates SQS queues, Lambda, RDS)
sam deploy --guided  # First time
sam deploy           # Subsequent deploys

# Configuration stored in samconfig.toml
# Uses AWS profile: eddy_tamusa_dev (edit samconfig.toml to change)
```

## Neo4j Knowledge Graph Schema

### Node Types (6)

1. **Vulnerability** - CVEs, GitHub Security Advisories (GHSA-*)
   - Properties: `canonical_id`, `title`, `summary`, `severity`, `published_at`
   - Constraint: `canonical_id` is UNIQUE
   - Indexed: `severity`, `published_at`

2. **Package** - Software packages (PyPI, npm, etc.)
   - Properties: `name`, `ecosystem`
   - Constraint: `name` is UNIQUE

3. **Weakness** - CWE (Common Weakness Enumeration)
   - Properties: `cwe_id`, `name`, `description`
   - Constraint: `cwe_id` is UNIQUE

4. **AttackTactic** - MITRE ATT&CK techniques/tactics
   - Properties: `mitre_id`, `name`, `description`, `tactic_type`
   - Constraint: `mitre_id` is UNIQUE
   - Indexed: `tactic_type`

5. **AttackPattern** - CAPEC attack patterns
   - Properties: `capec_id`, `name`, `description`, `likelihood`
   - Constraint: `capec_id` is UNIQUE

6. **DefenseControl** - Mitigation strategies and security controls
   - Properties: `control_id`, `name`, `description`
   - Constraint: `control_id` is UNIQUE

### Relationship Types (13)

- `EXPLOITS`: Vulnerability → Weakness (CVE exploits CWE weakness)
- `AFFECTS`: Vulnerability → Package (with `version_range` property)
- `ENABLES`: Vulnerability → AttackTactic (CVE enables MITRE technique)
- `IMPLEMENTS`: AttackTactic → AttackPattern (technique implements CAPEC)
- `TARGETS`: AttackPattern → Weakness (CAPEC targets CWE)
- `MITIGATES`: DefenseControl → AttackTactic (control mitigates technique)
- `REMEDIATES`: DefenseControl → Vulnerability (control remediates CVE)
- `SUB_TECHNIQUE_OF`: AttackTactic → AttackTactic (hierarchy)
- `CHILD_OF`: AttackPattern → AttackPattern (hierarchy)
- `DEPENDS_ON`: Package → Package (dependency graph)
- `HAS_VULNERABILITY`: Package → Vulnerability (package contains CVE)
- `REFERENCED_BY`: Any → ExternalResource (citations)
- `RELATED_TO`: Generic relationship (catch-all)

### Graph Queries (Cypher Examples)

**Find all CVEs exploiting SQL Injection:**
```cypher
MATCH (v:Vulnerability)-[:EXPLOITS]->(w:Weakness {cwe_id: 'CWE-89'})
RETURN v.canonical_id, v.severity, v.summary
```

**Attack chain discovery (2-hop traversal):**
```cypher
MATCH path = (v:Vulnerability)-[:ENABLES|IMPLEMENTS*1..2]->(ap:AttackPattern)
WHERE v.severity IN ['HIGH', 'CRITICAL']
RETURN path LIMIT 10
```

**Find affected packages by vulnerability:**
```cypher
MATCH (p:Package)<-[:AFFECTS]-(v:Vulnerability {canonical_id: 'CVE-2024-12345'})
RETURN p.name, p.ecosystem
```

## Code Patterns and Conventions

### Agent Invocation Pattern
All specialist agents follow this structure:
```python
def query_bedrock(prompt, data_snippet, agent_name="", file_origin=""):
    # Uses Llama 3 template format with <|begin_of_text|> tags
    # Returns extracted JSON or empty dict
```

Agents MUST return valid JSON with specific schema keys or the normalizer drops them.

### Database Connection Pattern
Always use connection pool:
```python
conn = get_db_connection()
try:
    # ... database operations
finally:
    release_db_connection(conn)
```

### URL Construction (Zero-Hallucination Pattern)
Programmatically construct source URLs (never let LLM generate):
```python
if source == 'nvd' or canonical_id.startswith('CVE-'):
    url = f"https://nvd.nist.gov/vuln/detail/{canonical_id}"
elif source == 'pypi':
    url = f"https://pypi.org/project/{package_name}/"
```

### Pre-LLM Deduplication Pattern
Extract canonical IDs from raw data and filter against database before queuing:
```python
def filter_new_items(raw_items: list[dict], package: str, source: str) -> list[dict]:
    existing_ids = get_existing_ids(package, source)  # Query DB once
    new_items = []
    for item in raw_items:
        item_id = extract_id_from_raw(item, source)  # Extract CVE-*, GHSA-*, etc.
        if item_id not in existing_ids:
            new_items.append(item)
    return new_items
```
This prevents wasting Bedrock tokens on already-normalized records.

### URL Validation Threading Pattern
Run URL validation async to avoid blocking main response:
```python
threading.Thread(
    target=validate_and_log_urls,
    args=(agent_name, file_origin, response_text),
    daemon=True
).start()
```
This validates all URLs in the response via HTTP HEAD requests and logs results to `url_validation_logs` without calling an LLM.

### GraphRAG Dual-Write Pattern
Write threat intelligence to both PostgreSQL and Neo4j simultaneously:
```python
from src.db import get_db_connection, insert_threat_record
from src.embeddings import generate_embedding
from src.graph_extractor import extract_triples, build_graph_data
from src.graph_db import batch_insert_graph

# 1. Generate embedding from summary
embedding = generate_embedding(normalized_record['summary'])

# 2. Write to PostgreSQL with embedding
conn = get_db_connection()
try:
    insert_threat_record(conn, normalized_record, embedding)
finally:
    release_db_connection(conn)

# 3. Extract graph triples from relationships field
triples = extract_triples(normalized_record.get('relationships', []))

# 4. Build Neo4j nodes and edges
nodes, edges = build_graph_data(triples, normalized_record)

# 5. Write to Neo4j (non-blocking, PostgreSQL succeeds even if this fails)
batch_insert_graph(nodes, edges)
```

### Hybrid Retrieval Pattern (GraphRAG)
Combine vector search, full-text search, and graph traversal:
```python
def hybrid_retrieval(user_query: str, package_name: str, top_k: int = 5):
    # 1. Generate query embedding
    query_embedding = generate_embedding(user_query)
    
    # 2. Vector similarity search (pgvector)
    vector_results = vector_search(query_embedding, package_name, top_k)
    
    # 3. Full-text search (PostgreSQL tsvector)
    fulltext_results = fulltext_search(user_query, package_name, top_k)
    
    # 4. Graph traversal (Neo4j Cypher)
    cve_ids = [r['canonical_id'] for r in vector_results]
    graph_results = graph_traverse(cve_ids, depth=2)  # Find related CVEs
    
    # 5. Merge and deduplicate results
    combined = merge_results(vector_results, fulltext_results, graph_results)
    
    return combined
```

### Neo4j Connection Pattern
Always use context manager for Neo4j sessions:
```python
from src.graph_db import get_neo4j_session

with get_neo4j_session() as session:
    result = session.run("""
        MATCH (v:Vulnerability)-[:EXPLOITS]->(w:Weakness)
        WHERE v.canonical_id = $cve_id
        RETURN w.cwe_id, w.name
    """, cve_id="CVE-2024-12345")
    
    for record in result:
        print(f"CWE: {record['w.cwe_id']} - {record['w.name']}")
```

### Embedding Generation Pattern
Generate embeddings for semantic search:
```python
from src.embeddings import generate_embedding

# Generate embedding from threat summary
summary = "SQL injection vulnerability in Django ORM allows authenticated users to execute arbitrary SQL queries"
embedding = generate_embedding(summary)  # Returns list of 1536 floats

# Store in PostgreSQL with pgvector
conn.execute(
    "INSERT INTO threat_intelligence_records (summary, embedding) VALUES (%s, %s)",
    (summary, embedding)
)
```

### Graph Extraction Pattern
Extract structured triples from agent relationships:
```python
from src.graph_extractor import extract_triples, build_graph_data

# Agent returns relationships in JSON
agent_response = {
    'relationships': [
        {'subject': 'CVE-2024-12345', 'predicate': 'EXPLOITS', 'object': 'CWE-89'},
        {'subject': 'CVE-2024-12345', 'predicate': 'AFFECTS', 'object': 'django', 'properties': {'version_range': '>=2.0,<3.0'}}
    ]
}

# Extract and validate triples
triples = extract_triples(agent_response['relationships'])

# Build Neo4j-compatible data structures
nodes, edges = build_graph_data(triples, normalized_record)

# nodes = [
#   {'labels': ['Vulnerability'], 'properties': {'canonical_id': 'CVE-2024-12345', ...}},
#   {'labels': ['Weakness'], 'properties': {'cwe_id': 'CWE-89', ...}}
# ]
# edges = [
#   {'from': 'CVE-2024-12345', 'to': 'CWE-89', 'type': 'EXPLOITS'}
# ]
```

### Summary Verification Pattern
Validate LLM-generated summaries against source content without LLM overhead:
```python
# 1. Initialize appropriate scraper based on source
if source == 'github_advisories':
    scraper = GitHubAdvisoryScraper()  # 2-second rate limit
else:
    scraper = NVDScraper()  # 6-second rate limit

# 2. Scrape source description
result = scraper.scrape_description(source_url)

# 3. Extract keywords using TF-IDF
extractor = KeywordExtractor(max_features=15)
keywords_llm = extractor.extract_keywords(llm_summary, max_keywords=10)
keywords_source = extractor.extract_keywords(scraped_content, max_keywords=15)

# 4. Calculate hybrid similarity
analyzer = SimilarityAnalyzer()
jaccard = analyzer.calculate_jaccard(keywords_llm, keywords_source)
fuzzy = analyzer.calculate_fuzzy(llm_summary, scraped_content)
combined = analyzer.combined_score(jaccard, fuzzy)  # 0.6*jaccard + 0.4*fuzzy

# 5. Determine verdict with adaptive threshold
is_short = len(llm_summary) < 20
verdict = analyzer.get_verdict(combined, is_short=is_short)  # MATCH/MISMATCH/UNVERIFIABLE
```
This approach eliminates LLM cost while providing deterministic, reproducible verification. Supports both NVD CVEs and GitHub Security Advisories.

## Important Constraints

**Rate Limits:**
- NVD API (unauthenticated): 6-second mandatory delay between requests
- AWS Bedrock: Worker implements exponential backoff (4s initial, doubles on throttle)
- Worker adds 1-second pause between successful Bedrock calls

**SQS Message Size:**
- PyPI releases are stripped before queuing (only `info` and `last_serial` retained)
- Maximum 256 KB per message
- Messages failing 3 times route to Dead Letter Queue (DLQ)

**Security:**
- Database password fetched from .env locally, AWS SSM Parameter Store in Lambda
- All RDS connections use `sslmode="require"`
- Neo4j Aura connections use TLS (`neo4j+s://` protocol)
- Neo4j password stored in AWS SSM Parameter Store: `NEO4J_PASSWORD`
- Guardrails detect keywords: EXPLOIT, WEAPON (case-insensitive)

**AWS Resources:**
- Lambda timeout: 180 seconds
- Lambda memory: 512 MB
- Reserved concurrent executions: 5 (commented out in template.yaml)
- SQS visibility timeout: 300 seconds

**Neo4j Aura Free Tier Limits:**
- **Nodes:** 200,000 maximum
- **Relationships:** 400,000 maximum
- **Storage:** 50 MB graph data
- **RAM:** 1 GB
- **Note:** Graph writes are non-blocking; if Neo4j fails, PostgreSQL still succeeds

## Configuration Files

- `.env`: Local credentials (never commit)
  - PostgreSQL: `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_PORT`
  - Neo4j: `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`
  - AWS: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `SQS_QUEUE_URL`
  - Optional: `GITHUB_TOKEN`, `NVD_API_KEY`
- `src/config.py`: Settings dataclass with environment variable loading (includes Neo4j config)
- `template.yaml`: AWS SAM CloudFormation template (includes Neo4j env vars)
- `samconfig.toml`: SAM deployment parameters (stack name: redteam-backend)
- `scripts/`: Local-only scripts (ingestion, DB initialization, Lambda layer cleanup)
- `src/.samignore`: Excludes `validators/` and `sources/` from Lambda deployment

## Database Schema

**threat_intelligence_records** (main threat intel table):
- Unique constraint on `(canonical_id, package_name)`
- Full-text search on `summary` using `to_tsvector('english', summary)`
- **`embedding` column (vector(1536)):** Stores Bedrock Titan embeddings for semantic search
  - Populated automatically by Lambda worker during ingestion
  - Enables cosine similarity search: `ORDER BY embedding <=> query_vector LIMIT 10`
  - Index: `CREATE INDEX ON threat_intelligence_records USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);`
- Columns: id, run_id, package_name, source, record_type, canonical_id, title, summary, severity, published_at, references_json, embedding, verification_status, last_verified_at

**url_validation_logs**:
- Tracks URL validation results from agent responses
- Stores detailed URL validation JSON with HTTP status codes
- Populated by async URL validator threads
- Columns: id, timestamp, file_origin, agent_name, hallucination_detected, hallucination_reason, url_validation_json

**graph_execution_metrics**:
- Performance tracking: retrieval_latency_sec, analysis_latency_sec, total_latency_sec
- Guardrail trigger counts and execution step counts
- Per-package granularity
- Columns: id, evaluated_at, package_target, retrieval_latency_sec, analysis_latency_sec, total_latency_sec, cves_correlated, mitre_capec_linked, guardrail_triggered, total_steps

**summary_verification_logs**:
- Links to `threat_intelligence_records` via `threat_intel_record_id`
- Stores scraped source content and HTTP status
- Keywords extracted from both LLM summary and source (TEXT arrays)
- Similarity scores: jaccard_score, fuzzy_score, combined_score
- Verdict: 'MATCH', 'MISMATCH', or 'UNVERIFIABLE'
- Scrape status tracking: 'success', 'not_found', 'blocked', 'timeout', 'error'
- Populated by `src/validators/summary_verifier.py` module
- Columns: id, threat_intel_record_id, verified_at, source_url, scrape_status, scraped_content, http_status, keywords_llm, keywords_source, jaccard_score, fuzzy_score, combined_score, verdict, error_msg

**ingestion_logs**:
- Tracks raw data fetching operations
- Records HTTP status, errors, and raw data file paths
- Columns: id, run_id, package_name, source, endpoint, fetched_at_utc, http_status, error, raw_path

## Project Structure

```
LLM_Agent_RedTeaming/
├── src/                           # Lambda-deployed code (CodeUri in template.yaml)
│   ├── lambda_worker.py           # Lambda entry point (SQS event handler)
│   ├── agents.py                  # Multi-agent specialists (PyPI, NVD, GitHub, MITRE, CAPEC)
│   ├── db.py                      # PostgreSQL connection pooling + insert operations
│   ├── graph_db.py                # Neo4j connection management + batch insert
│   ├── graph_extractor.py         # Extract entities/relationships from agent output
│   ├── embeddings.py              # Bedrock Titan embedding generation
│   ├── config.py                  # Configuration dataclass (env vars)
│   ├── metrics.py                 # Performance tracking
│   ├── validators/                # ❌ Excluded by .samignore (local verification only)
│   │   ├── url_validator.py      # HTTP HEAD request validation
│   │   └── summary_verifier.py   # TF-IDF + Jaccard similarity verification
│   └── sources/                   # ❌ Excluded by .samignore (used by ingestion scripts)
│       ├── pypi.py                # PyPI API fetcher
│       ├── nvd.py                 # NVD API fetcher
│       └── github_advisories.py  # GitHub GraphQL fetcher
│
├── scripts/                       # ❌ Local-only scripts (NOT deployed to Lambda)
│   ├── ingest_to_sqs.py           # Data ingestion orchestrator
│   ├── init_cloud_db.py           # PostgreSQL schema provisioning
│   ├── init_neo4j_schema.py       # Neo4j constraints + indexes
│   ├── clean_lambda_layer.py      # Lambda layer size optimizer
│   ├── fetchers.py                # MITRE/CAPEC fetchers
│   ├── state.py                   # Incremental ingestion state
│   ├── tools.py                   # Utility functions
│   └── utils.py                   # File I/O helpers
│
├── test/                          # Test suite
│   ├── test_graphrag.py           # GraphRAG integration tests
│   ├── run_worker.py              # Local worker daemon
│   └── ...
│
├── cti_dependencies/              # Lambda layer dependencies
│   ├── requirements.txt           # Full dependencies (local dev)
│   ├── requirements-lambda.txt    # Minimal dependencies (Lambda only)
│   └── python/                    # Installed packages (sam build output)
│
├── graph_agents.py                # LangGraph workflow (researcher → analyzer → interception)
├── api.py                         # FastAPI backend (SSE streaming)
├── app_dashboard.py               # Streamlit dashboard
├── template.yaml                  # AWS SAM CloudFormation template
├── samconfig.toml                 # SAM deployment config
├── CLAUDE.md                      # This file (project documentation)
└── README.md                      # User-facing documentation
```

### Key Separation Principles

1. **`src/` = Lambda deployment surface**
   - Only code here is packaged into Lambda ZIP
   - `src/.samignore` excludes `validators/` and `sources/` (heavyweight dependencies)
   
2. **`scripts/` = Local operations**
   - Data ingestion, database setup, deployment utilities
   - NOT included in `CodeUri: src/` so never deployed to Lambda
   - Uses absolute imports: `from src.db import ...`

3. **`cti_dependencies/` = Lambda layer**
   - **`requirements.txt`**: Ultra-minimal Lambda deps (3 packages: neo4j, psycopg2-binary, pydantic, ~20 MB)
     - Used by SAM build and `scripts/clean_lambda_layer.py`
   - **`requirements-full.txt`**: Complete local dev environment (14 packages, ~130 MB)
     - Includes langchain, langgraph for LangGraph workflow
     - Use for local development with `pip install -r cti_dependencies/requirements-full.txt`


## AWS Profile Configuration

Project uses AWS SSO profile `eddy_tamusa_dev`. Before running:
```bash
aws sso login --profile eddy_tamusa_dev
# or
aws configure sso
```

Verifier and agents use `AWS_PROFILE_NAME` environment variable, fallback to `AWS_PROFILE`, then `default`.
