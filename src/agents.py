import requests
import json
from .config import OLLAMA_URL, OLLAMA_MODEL

def query_ollama(prompt, data_snippet):
    """Sends the prompt and data to the local Ollama LLM."""
    content = f"{prompt}\n\nDATA SNIPPET:\n{json.dumps(data_snippet)[:2000]}"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": content}],
        "stream": False,
        "format": "json"
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
        resp.raise_for_status()
        
        raw_output = resp.json()["message"]["content"]
        print(f"\n[LLM RAW OUTPUT]:\n{raw_output}\n")
        
        return json.loads(raw_output)
    except Exception as e:
        print(f"      [!] Agent Error: {e}")
        return {}

def _execute_specialist(raw_items, prompt, source_name):
    """Hidden helper function so we don't repeat the loop code 5 times."""
    candidates = []
    print(f"    [{source_name.upper()} Agent] Analyzing {len(raw_items)} items...")
    for item in raw_items:
        result = query_ollama(prompt, item)
        if result and result.get("id"):
            result["_origin_source"] = source_name
            candidates.append(result)
            print("x", end="", flush=True)
        else:
            print(".", end="", flush=True)
    print()
    return candidates


# ==========================================
# RETRIEVAL LAYER: ONE AGENT PER DATA SOURCE
# ==========================================

def run_pypi_agent(raw_items):
    prompt = "You are a PyPI Analyst extracting package metadata. Output ONLY a valid JSON object with 'id' (package name) and 'desc' (summary). CRITICAL: Do NOT wrap the JSON in markdown code blocks or backticks. Output nothing but the raw JSON object. Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "pypi")

def run_github_agent(raw_items):
    prompt = "You are a GitHub Security Analyst extracting vulnerability details. Output ONLY a valid JSON object with 'id' (GHSA ID), 'desc' (description), 'cvss' (severity). CRITICAL: Do NOT wrap the JSON in markdown code blocks or backticks. Output nothing but the raw JSON object. Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "github")

def run_nvd_agent(raw_items, package_name):
    """
    Agent specifically dedicated to NVD CVEs.
    Now uses Ecosystem Anchoring to prevent cross-contamination.
    """
    prompt = f"""
    You are an NVD Vulnerability Analyst for the PYTHON ecosystem.
    TASK: Extract CVE details specifically for the Python package '{package_name}'.
    
    CRITICAL FILTER RULES (RQ2):
    1. If the vulnerability does NOT affect Python or a Python web framework, it is a FALSE POSITIVE.
    2. If the description mentions ANY of the following keywords, it is a FALSE POSITIVE: "Xen", "hypervisor", "Linux kernel", "C++ buffer overflow", "FLASK_AVC".
    3. If it is a FALSE POSITIVE, you MUST return {{}} and nothing else.
    
    Output ONLY a valid JSON object with 'id' (CVE ID), 'desc' (description), 'cvss' (severity). 
    Do NOT use markdown.
    """
    return _execute_specialist(raw_items, prompt, "nvd")

def run_mitre_agent(raw_items):
    prompt = "You are a Threat Hunting Agent extracting technique details. Output ONLY a valid JSON object with 'id' (external ID), 'name' (technique name), 'details' (description). CRITICAL: Do NOT wrap the JSON in markdown code blocks or backticks. Output nothing but the raw JSON object. Return {} if not an attack-pattern."
    return _execute_specialist(raw_items, prompt, "attack")

def run_capec_agent(raw_items):
    prompt = "You are an AppSec Expert extracting exploit mechanics from CAPEC data. Output ONLY a valid JSON object with 'id' (CAPEC ID), 'name' (attack name), 'details' (description). CRITICAL: Do NOT wrap the JSON in markdown code blocks or backticks. Output nothing but the raw JSON object. Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "capec")


# ==========================================
# NORMALIZING LAYER: ONE CENTRAL AGENT
# ==========================================

def run_central_normalizer(specialist_outputs, source_name):
    prompt = f"""
    You are the {source_name.upper()} Data Normalizer.
    Input: A semi-structured JSON object from a specialist agent.
    Task: Map it strictly to the database schema.
    
    CRITICAL ID RULES (RQ2):
    1. CANONICAL ID: Extract the standard industry identifier.
       - MITRE: ID starts with 'T' (e.g., T1033). 
       - CAPEC: ID starts with 'CAPEC-' (e.g., CAPEC-103).
       - NVD: ID starts with 'CVE-'.
       - NEVER use long UUIDs (e.g., attack-pattern--8782...).
    
    2. THE ESCAPE HATCH (CRITICAL): If the input ONLY contains a long UUID and no standard ID is available, you MUST set "canonical_id": null. Do NOT invent or guess an ID.

    Target Schema:
    {{
      "source": "{source_name}",
      "record_type": "cve, attack-pattern, package, or advisory",
      "canonical_id": "Canonical ID ONLY (e.g. CVE-XXX, TXXX, CAPEC-XXX), or null",
      "title": "Short technical title",
      "summary": "1-sentence technical summary. DO NOT TRUNCATE KEYWORDS.",
      "severity": "HIGH, MEDIUM, LOW, CRITICAL, or null",
      "published_at": "ISO Date or null",
      "references": []
    }}
    Output ONLY raw JSON. Do not include markdown code blocks.
    """
    
    print(f"    [Normalizer Agent] Processing {len(specialist_outputs)} {source_name} items...")
    normalized_results = []
    
    for item in specialist_outputs:
        result = query_ollama(prompt, item)
        if result and result.get("canonical_id"):
            normalized_results.append(result)
            print("+", end="", flush=True)
        else:
            print("-", end="", flush=True)
    print()
    return normalized_results
    