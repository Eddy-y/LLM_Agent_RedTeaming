# Multi-Agent CTI Red Teaming & Augmentation Pipeline

This project implements a fully local, multi-agent Cyber Threat Intelligence (CTI) architecture. It uses Large Language Models (LLMs) to automatically ingest, normalize, and synthesize threat data from multiple disparate sources into actionable security reports.

## 🏗️ System Architecture

The system is divided into two distinct layers to ensure data integrity and clear separation of concerns:

### 1. The Ingestion & Normalization Layer (`src/pipeline.py` & `src/agents.py`)
This backend pipeline runs asynchronously to build a unified Knowledge Graph. It features explicit LLM agents dedicated to specific tasks:
* **Data Source Specialists (The Retrievers):** Dedicated agents (`run_nvd_agent`, `run_pypi_agent`, `run_github_agent`, `run_mitre_agent`, `run_capec_agent`) extract core security facts from raw, messy JSON APIs.
* **Central Normalizer Agent:** A boss agent that evaluates the specialists' outputs and forces them into a strict, unified SQLite database schema (`normalized_items`). It actively rejects hallucinated or malformed data.

### 2. The Augmentation & Interface Layer (`chat_UI.py` & `run_agents.py`)
This frontend layer utilizes a **LangGraph** state machine to interact with the user and the database.
* **Agent 1 (The Scout):** Evaluates the user's target package and executes a strict tool call (`search_local_cti`) to pull relevant vulnerabilities and attack patterns from the local database.
* **Agent 2 (The Augmentation Agent):** The CTI Detective. It reads the isolated CVEs and connects them to broader MITRE/CAPEC attack patterns, writing "bridge statements" that explain *how* a specific software flaw enables a real-world attacker behavior.

## 🚀 Prerequisites

1. **Python 3.10+**
2. **Ollama:** Installed locally for running the LLMs.
3. **Local LLM:** Pull the required model via terminal:
   ```bash
   ollama pull llama3.2
   ```
4. **Dependencies:** Install the required Python packages:
   ```bash
   pip install langchain langchain-core langgraph streamlit requests python-dotenv pandas
   ```

## ⚙️ How to Run the Project

### Phase 1: Build the CTI Database (The Night Shift)
First, run the backend pipeline to fetch, analyze, and normalize the threat data. This will create and populate the SQLite database.

```bash
python3 -m src.pipeline
```
> **Note:** You will see the LLM actively processing MITRE/CAPEC corpora and package-specific data in the terminal, indicating successful database insertions with `+` symbols.

### Phase 2: Launch the Augmentation UI (The Day Shift)
Once the database is built, launch the Streamlit interface to interact with the CTI Augmentation Agent.

```bash
python3 -m streamlit run chat_UI.py
```
1. Open the provided localhost URL in your browser.
2. Enter a target package (e.g., `flask`, `django`, `requests`).
3. Click "Run Evaluation" to watch the LangGraph multi-agent system query the local DB and generate a synthesized threat report.

## 📁 Key File Structure

* `chat_UI.py` - The Streamlit frontend.
* `run_agents.py` - The LangGraph state machine and Augmentation Agent logic.
* `src/pipeline.py` - Orchestrates the ingestion of web APIs.
* `src/agents.py` - Houses the explicit Specialist Agents and Central Normalizer.
* `src/tools.py` - Contains the `search_local_cti` tool bridging the AI to the SQLite DB.
* `src/fetchers.py` - Handles batch downloading of universal corpora (MITRE/CAPEC).
* `data/` - Auto-generated folder containing the `pipeline.sqlite` database and raw JSON logs.
