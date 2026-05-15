Here is the updated `README.md` rewritten to accurately reflect your new cloud-native AWS architecture, the decoupled FastAPI backend, and the Amazon Bedrock LLM integrations.

```markdown
# Multi-Agent CTI Red Teaming & Augmentation Pipeline (AWS Native)

This project implements a fully scalable, cloud-native multi-agent Cyber Threat Intelligence (CTI) architecture. It uses Amazon Bedrock Large Language Models (LLMs) to automatically ingest, normalize, and synthesize threat data from multiple disparate sources into actionable security reports for the Python ecosystem.

## 🏗️ System Architecture

The system has been designed for high concurrency and decoupling, utilizing AWS managed services to prevent database locking and bottlenecking. It is divided into two distinct layers:

### 1. The Ingestion & Normalization Layer (The "Night Shift")
This backend asynchronous pipeline is driven by **Amazon SQS** and **AWS Lambda** to build a unified Knowledge Graph in an **Amazon RDS (PostgreSQL)** database.
* **The Fetcher (`src/ingest_to_sqs.py`):** Extracts raw JSON from external APIs (NVD, PyPI, GitHub, MITRE, CAPEC) and pushes individual payloads to the `CTI-Ingestion-Queue`.
* **The Workers (`src/lambda_worker.py`):** AWS Lambda functions trigger on SQS messages to process data concurrently using **Amazon Bedrock**.
* **Specialist & Normalizer Agents (`src/agents.py`):** The Lambda worker invokes explicit LLM agents dedicated to specific tasks (e.g., NVD filtering via Ecosystem Anchoring) and passes the extracted facts to a Central Normalizer to ensure strict database schema adherence.

### 2. The Augmentation & Interface Layer (The "Day Shift")
This frontend layer exposes the CTI Augmentation Agent as a decoupled REST API using **FastAPI** and **LangGraph**.
* **The Interface (`api.py`):** A FastAPI application that receives requests to analyze specific Python packages.
* **The Graph Engine (`graph_agents.py`):** A LangGraph state machine. It features a "Researcher Node" that performs heuristic SQL queries against the RDS database, and an "Analyzer Node" that uses Amazon Bedrock to synthesize the retrieved threat data into a structured mitigation report.

## 🚀 Prerequisites

1. **AWS Account & Credentials:** Configured locally via AWS CLI (`~/.aws/credentials`).
2. **Amazon Bedrock Access:** You must request access to the Meta Llama 3 models (e.g., `meta.llama3-8b-instruct-v1:0`) in the AWS `us-east-1` region.
3. **Python 3.10+**
4. **Dependencies:** ```bash
   pip install fastapi uvicorn boto3 psycopg2-binary langchain langchain-aws langgraph python-dotenv

```

## ⚙️ How to Run the Project

### Phase 1: Infrastructure & Database Provisioning

First, deploy your AWS infrastructure (SQS queues, Lambda concurrency limits, RDS instances) using the provided SAM template.

```bash
sam deploy -t template.yaml --guided

```

Once the RDS instance is live, initialize the PostgreSQL schema and metrics tracking tables:

```bash
python3 init_cloud_db.py

```

### Phase 2: Build the CTI Database (Data Ingestion)

Run the fetching script. Instead of processing locally, this will rapidly pull data and offload the actual LLM extraction to your highly concurrent AWS Lambda workers via SQS.

```bash
python3 -m src.ingest_to_sqs

```

> **Note:** Monitor your AWS CloudWatch logs for the Lambda function to see the Bedrock agents normalizing data and inserting it into RDS.

### Phase 3: Launch the Augmentation API

Spin up the FastAPI backend to interact with your synthesized threat intelligence.

```bash
uvicorn api:app --reload

```

1. Send a POST request to `http://localhost:8000/generate_report` with a payload like `{"package_name": "flask"}`.
2. The LangGraph agent will execute, track research metrics (latency, correlations), log them to the RDS `evaluation_metrics` table, and return the final report.

## 📁 Key File Structure

* `api.py` - The FastAPI backend serving the LangGraph execution endpoint.
* `graph_agents.py` - The LangGraph state machine (Researcher & Analyzer nodes).
* `init_cloud_db.py` - Provisions the PostgreSQL schema on Amazon RDS.
* `template.yaml` - AWS IaC template defining SQS, Lambda configurations, and RDS.
* `src/ingest_to_sqs.py` - The orchestrator that fetches external data and pushes to SQS.
* `src/lambda_worker.py` - The AWS Lambda entry point for processing SQS events.
* `src/agents.py` - Houses the explicit LLM Specialist Agents used by Lambda via Bedrock.
* `src/db.py` - Handles standard PostgreSQL connections, bulk inserts, and fetch logs.

```

```