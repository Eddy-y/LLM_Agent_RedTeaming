# Agentic Threat Intelligence & Red Teaming Framework (PoC)

## 📖 Project Overview

This repository represents the **initial Proof of Concept (PoC)** for a larger research initiative into **Retrieval Augmented Generation (RAG)-based agentic LLMs**. The broader goal is to emulate cyberattackers’ tactics, techniques, and procedures (TTPs) to quantify how multi-agent AI frameworks can accelerate adversary workflows and derive defense-in-depth mitigation strategies.

**Current Phase: Autonomous Intelligence Ingestion**
This specific implementation focuses on **Objective 1**: designing a lightweight, autonomous agent capable of ingesting, normalizing, and correlating threat intelligence from heterogeneous sources (PyPI, GitHub Advisories, NVD) in near-real-time without human pre-labeling.

---

## 🎯 Research Scope & Objectives

This project addresses the following research questions regarding the efficacy and safety of autonomous security agents:

### Research Questions

* **RQ1:** Can distributed, lightweight LLM agents reliably ingest and maintain near-real-time threat intelligence from heterogeneous cybersecurity corpora?
* **RQ2:** Can a centralized retriever agent effectively normalize and correlate vulnerabilities across multiple sources?
* **RQ3:** Can the system support analyst-oriented querying while preventing the generation of actionable weaponizable guidance?
* **RQ4:** How resilient are the system’s guardrails to adversarial probing?

### Core Objectives

1. **Real-Time Corpus-Specific Intelligence Collection:** Deploy agents to continuously monitor authoritative knowledge bases (MITRE ATT&CK, CAPEC, CWE, CVE, NVD).
2. **Centralized Correlation:** Perform semantic normalization and schema alignment to construct a unified threat graph.
3. **Query-Driven Reasoning with Guardrails:** Enable interactive querying while strictly enforcing safety protocols.

---

## ⚙️ Technical Architecture (PoC)

This Phase 1 implementation utilizes a **Human-in-the-Loop (HiL)** architecture powered by local LLMs to ensure data privacy and controlled evaluation.

* **Orchestration:** [LangGraph](https://python.langchain.com/docs/langgraph) (Stateful multi-step reasoning loops).
* **Reasoning Engine:** Local LLMs via [Ollama](https://ollama.com/) (Llama 3, Phi-3).
* **Tools & Tools Calling:** Custom Python wrappers for:
* **PyPI JSON API:** Metadata verification.
* **GitHub GraphQL API:** Security advisory retrieval.
* **NVD (NIST) API:** CVE scoring and timeline analysis.


* **Evaluation:** JSONL logging of the agent's "Thought Process" to analyze reasoning capabilities and hallucination rates.

---

## 📂 Project Structure

```bash
.
├── agents.py           # Defines the LangGraph state machine and agent "Brain"
├── run_agents.py       # Main execution script (Batch processing & Evaluation logging)
├── engine.py           # LLM initialization (Ollama configurations)
├── src/
│   ├── tools.py        # Tool definitions exposed to the Agent
│   ├── config.py       # Environment configuration & Settings
│   ├── db.py           # SQLite handlers for raw data storage
│   └── sources/        # Raw API fetchers (pypi.py, nvd.py, etc.)
├── data/
│   ├── evaluation_results.jsonl # detailed reasoning logs (Step-by-step thoughts)
│   └── agent_summary.csv        # Final structured reports
└── requirements.txt    # Python dependencies

```

---

## 🚀 Setup Guide

### Prerequisites

1. **Python 3.10+** installed.
2. **Ollama** installed and running locally.
3. **API Keys:**
* GitHub Token (Classic PAT) with `read:packages` permissions.
* NVD API Key (Optional, but recommended for rate limits).



### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/llm-redteaming-agent.git
cd llm-redteaming-agent

```


2. **Create a Virtual Environment:**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

```


3. **Install Dependencies:**
```bash
pip install -r requirements.txt

```


4. **Pull the Local Model:**
Ensure Ollama is running, then pull the model defined in `engine.py` (default: Llama 3):
```bash
ollama pull llama3

```



### Configuration

Set your environment variables. You can do this in your terminal or create a `.env` file:

```bash
# Required for GitHub Advisories
export GITHUB_TOKEN="ghp_your_token_here"

# Optional: NVD API Key
export NVD_API_KEY="your_nvd_key_here"

```

---

## 🕵️ Usage

To run the autonomous Red Teaming evaluation:

```bash
python run_agents.py

```

### What happens next?

1. The system connects to the local SQLite database to identify target packages.
2. The **Agent** initializes its cognitive graph (Reason -> Act -> Observe).
3. It autonomously decides which tools to call (PyPI, GitHub, NVD) based on what it finds.
4. It generates two output files:
* `data/agent_summary.csv`: A high-level security report for each package.
* `data/evaluation_results.jsonl`: A detailed log of every "thought," "tool call," and "observation" for research analysis.



---

## ⚠️ Disclaimer

**Research Purpose Only.** This tool is designed for **defensive security research** and **academic evaluation** of Large Language Models. It operates in a read-only capacity against public APIs. The developers are not responsible for misuse of this tool. Ensure you comply with the Terms of Service for all queried APIs (GitHub, NIST, PyPI).

---

## 📜 License

[MIT License](https://www.google.com/search?q=LICENSE)