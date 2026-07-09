# Scripts Directory

Local-only scripts for CTI platform operations. **These files are NOT deployed to AWS Lambda.**

## Purpose

This directory contains scripts that run on your local machine or CI/CD pipeline, but are not part of the Lambda function deployment. By separating them from `src/`, we:

1. **Reduce Lambda package size** (faster cold starts)
2. **Clarify deployment boundaries** (what runs where)
3. **Avoid `.samignore` issues** (files outside `CodeUri` are never packaged)

## Scripts

### Data Ingestion
- **`ingest_to_sqs.py`** - Fetches data from external APIs and queues to SQS
  ```bash
  python scripts/ingest_to_sqs.py
  ```

### Database Setup
- **`init_cloud_db.py`** - Provisions PostgreSQL schema (run once)
  ```bash
  python -m scripts.init_cloud_db
  ```
- **`init_neo4j_schema.py`** - Creates Neo4j constraints and indexes (run once)
  ```bash
  python -m scripts.init_neo4j_schema
  ```

### Deployment
- **`clean_lambda_layer.py`** - Optimizes Lambda layer size before deployment
  ```bash
  python scripts/clean_lambda_layer.py
  ```

### Utilities
- **`fetchers.py`** - MITRE ATT&CK and CAPEC data fetching
- **`state.py`** - State management for incremental ingestion
- **`tools.py`** - Shared utility functions
- **`utils.py`** - File I/O and formatting helpers

## Usage Pattern

All scripts use absolute imports to reference production code:

```python
# Import Lambda-deployed modules
from src.db import get_db_connection
from src.config import get_settings

# Import other scripts
from scripts.utils import ensure_dir
```

## What's Deployed to Lambda?

Only code in `src/` (except `src/validators/` and `src/sources/`) is deployed to Lambda:
- `src/lambda_worker.py` - Lambda entry point
- `src/agents.py` - LLM specialist agents
- `src/db.py` - Database connection pooling
- `src/graph_db.py` - Neo4j graph operations
- `src/graph_extractor.py` - Entity/relationship extraction
- `src/embeddings.py` - Bedrock Titan embeddings
- `src/config.py` - Configuration management
- `src/metrics.py` - Performance tracking

See `template.yaml` for the complete Lambda configuration.
