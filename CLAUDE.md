# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

An autonomous Cyber Threat Intelligence (CTI) platform that harvests security feeds, normalizes them via multi-agent LLM orchestration (AWS Bedrock), and provides real-time analytics with hallucination verification and adversarial guardrails. The architecture separates heavy data ingestion from interactive UI using an AWS SQS message queue worker pattern.

**Core Research Questions (RQ) addressed:**
- RQ2: Semantic search with zero-hallucination URL construction
- RQ3: Active interception guardrails for weaponization prevention
- RQ4: Red-team adversarial emulation testing

## Architecture

### Data Flow Pipeline
1. **Ingestion** (`src/ingest_to_sqs.py`) → Fetches from PyPI, NVD, GitHub Advisories, MITRE ATT&CK, CAPEC → Pushes to AWS SQS
2. **Queue** (AWS SQS) → Decouples ingestion from processing
3. **Worker** (`src/lambda_worker.py`) → Lambda function or local daemon drains queue → Routes to specialist agents → Normalizes → Writes to RDS
4. **LangGraph Engine** (`graph_agents.py`) → Conversational intelligence with researcher → analyzer → interception nodes
5. **Validation** (`src/validators/`) → URL validation and summary verification modules

### Key Components

**Multi-Agent System** (`src/agents.py`)
- Source-specific specialists: PyPI, GitHub, NVD, MITRE, CAPEC agents
- Central normalizer unifies schema across all sources
- All agents use AWS Bedrock (Llama 3 8B by default)

**LangGraph Workflow** (`graph_agents.py`)
- `researcher_node`: Fetches semantic CTI data from RDS using PostgreSQL full-text search
- `analyzer_node`: Generates threat reports with strict source URL preservation
- `interception_node`: Safety guardrail that blocks weaponization requests
- `build_attacker_graph()`: Red-team testing harness with jailbreak attempts

**Database** (`src/db.py`)
- ThreadedConnectionPool (1-20 connections)
- Tables: `threat_intelligence_records`, `ingestion_logs`, `graph_execution_metrics`, `url_validation_logs`, `summary_verification_logs`
- PostgreSQL with pgvector extension for semantic search

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
- **NVDScraper**: Web scraper with 6-second rate limiting, retry logic, and fallback CSS selectors
- **KeywordExtractor**: TF-IDF-based keyword extraction with security-domain stopwords
- **SimilarityAnalyzer**: Hybrid scoring using Jaccard coefficient (0.6 weight) + fuzzy token matching (0.4 weight)
- **VerificationOrchestrator**: Coordinates workflow, logs results to `summary_verification_logs` table
- Verdict thresholds: MATCH (≥0.4 combined score), MISMATCH (<0.4), UNVERIFIABLE (scrape failed)
- Short summary adjustment: Lower threshold to 0.3 for summaries <20 characters
- Zero cost per verification (vs. $0.001 for LLM-based verification)
- Performance: ~7-8 seconds per record including mandatory NVD rate limit

## Development Commands

### Environment Setup
```bash
# Create .env file with required credentials (see README for full list)
# Key variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, SQS_QUEUE_URL
# Database: DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, DB_PORT
# Optional: GITHUB_TOKEN, NVD_API_KEY

# Initialize database schema (run once or after schema changes)
python -m src.init_cloud_db

# If migrating from old table names, run migration script first:
python -m src.migrate_table_names
```

### Data Pipeline Operations

**Step 1: Ingest raw data to SQS queue**
```bash
python -m src.ingest_to_sqs
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

# Verbose mode with keyword/score output
python -m src.validators.summary_verifier --batch-size 10 --verbose
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

### Summary Verification Pattern
Validate LLM-generated summaries against source content without LLM overhead:
```python
# 1. Scrape source description with rate limiting
scraper = NVDScraper()
result = scraper.scrape_description(nvd_url)  # 6-second delay built-in

# 2. Extract keywords using TF-IDF
extractor = KeywordExtractor(max_features=15)
keywords_llm = extractor.extract_keywords(llm_summary, max_keywords=10)
keywords_source = extractor.extract_keywords(scraped_content, max_keywords=15)

# 3. Calculate hybrid similarity
analyzer = SimilarityAnalyzer()
jaccard = analyzer.calculate_jaccard(keywords_llm, keywords_source)
fuzzy = analyzer.calculate_fuzzy(llm_summary, scraped_content)
combined = analyzer.combined_score(jaccard, fuzzy)  # 0.6*jaccard + 0.4*fuzzy

# 4. Determine verdict with adaptive threshold
is_short = len(llm_summary) < 20
verdict = analyzer.get_verdict(combined, is_short=is_short)  # MATCH/MISMATCH/UNVERIFIABLE
```
This approach eliminates LLM cost while providing deterministic, reproducible verification.

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
- Guardrails detect keywords: EXPLOIT, WEAPON (case-insensitive)

**AWS Resources:**
- Lambda timeout: 180 seconds
- Lambda memory: 512 MB
- Reserved concurrent executions: 5 (commented out in template.yaml)
- SQS visibility timeout: 300 seconds

## Configuration Files

- `.env`: Local credentials (never commit)
- `src/config.py`: Settings dataclass with environment variable loading
- `template.yaml`: AWS SAM CloudFormation template
- `samconfig.toml`: SAM deployment parameters (stack name: redteam-backend)

## Database Schema

**threat_intelligence_records** (main threat intel table):
- Unique constraint on `(canonical_id, package_name)`
- Full-text search on `summary` using `to_tsvector('english', summary)`
- Optional `embedding` column (vector(1536)) for future semantic search
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

## AWS Profile Configuration

Project uses AWS SSO profile `eddy_tamusa_dev`. Before running:
```bash
aws sso login --profile eddy_tamusa_dev
# or
aws configure sso
```

Verifier and agents use `AWS_PROFILE_NAME` environment variable, fallback to `AWS_PROFILE`, then `default`.
