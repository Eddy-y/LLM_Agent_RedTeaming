# Project Pipeline Documentation

This document explains the architectural decisions and data flow of the security data ingestion pipeline.

---

## 1. The Strategy: "Messy Retrieval" vs. Precision

**The Question:** "How is it that we pull the relevant information or if we don't and we pull everything, why?"

**The Answer:** Your pipeline uses a **"Targeted but Broad"** strategy. It does not pull "everything" (the whole internet), but it also does not perfectly filter for "relevant" info before the agent sees it.

### How it works:
* **PyPI (Exact Metadata):** You hit the specific API endpoint for a package (e.g., `pypi.org/pypi/flask/json`). This returns everything about that package (version, author, license), which is highly relevant.
* **GitHub (Structured Filtering):** You use a GraphQL query to ask specifically for advisories where `ecosystem: PIP` and `package: [name]`. This is very precise.
* **NVD (Keyword Heuristics):** You use a `keywordSearch` for the package name. This is where you pull **"messy" data**. Searching for "flask" returns *Python Flask*, but also *"Xen Flask"* (a hypervisor tool).

### Why do we do this?
As stated in the **Project Outline**, the goal is **Red Teaming the Agent**, not building a perfect database. The project explicitly wants to *"pull in messy real world security related data and let the LLM itself try to make sense of it."*

If you cleaned the data perfectly in Python code before the agent saw it, you wouldn't be testing the agent's ability to **reason, filter noise, or handle ambiguity** (RQ2 in your Research Questions).

---

## 2. The `src/sources/` Folder (The "Fetchers")

This folder contains the adapters that know how to talk to specific external APIs. Each file follows the exact same "Fetch & Extract" pattern to keep the code modular.

* **`pypi.py`**
    * **Fetch:** Hits the JSON API.
    * **Extract:** Grabs the summary, home page, and version.
* **`github_advisories.py`**
    * **Fetch:** Authenticates with your `GITHUB_TOKEN` and handles pagination.
    * **Extract:** Standardizes the `ghsaId`, summary, and severity.
* **`nvd.py`**
    * **Fetch:** Uses the NIST API with your `NVD_API_KEY`.
    * **Extract:** Digs through the deeply nested JSON to find the English description and CVSS v3.1 score.

> **Why split this way?** If the NVD API changes its URL next week, you only have to edit `nvd.py`. The rest of your agent code remains untouched.

---

## 3. The `src/` Folder (The "Orchestrator")

This folder manages the infrastructure that supports the fetchers.

| File | Role | Description |
| :--- | :--- | :--- |
| **`pipeline.py`** | Legacy Logic | This was the manual script. It looped through packages and saved raw JSON. The new **Agent** now replaces this logic but still uses the `src/sources` functions. |
| **`config.py`** | Control Center | Loads secrets (`GITHUB_TOKEN`) and defines target packages (Flask, Django, etc.). |
| **`db.py`** | Storage | Handles **SQLite** operations to save extracted items for a permanent record. |
| **`utils.py`** | Helpers | General utility functions for file I/O and generating timestamps. |

## 4. Project Objective
The goal is Red Teaming the Agent, not building a perfect database. The project explicitly wants to "pull in messy real world security related data and let the LLM itself try to make sense of it". If you cleaned the data perfectly in Python code before the agent saw it, you wouldn't be testing the agent's ability to reason, filter noise, or handle ambiguity (Research Question)