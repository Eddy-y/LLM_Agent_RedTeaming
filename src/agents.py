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
    """Agent specifically dedicated to PyPI metadata."""
    prompt = "You are a PyPI Analyst. Extract package metadata. Output a JSON object with 'id' (package name), 'desc' (summary). Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "pypi")

def run_github_agent(raw_items):
    """Agent specifically dedicated to GitHub Advisories."""
    prompt = "You are a GitHub Security Analyst. Extract vulnerability details. Output a JSON object with 'id' (GHSA ID), 'desc' (description), 'cvss' (severity). Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "github")

def run_nvd_agent(raw_items):
    """Agent specifically dedicated to NVD CVEs."""
    prompt = "You are an NVD Vulnerability Analyst. Extract CVE details. Output a JSON object with 'id' (CVE ID), 'desc' (description), 'cvss' (severity). Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "nvd")

def run_mitre_agent(raw_items):
    """Agent specifically dedicated to MITRE ATT&CK."""
    prompt = "You are a Threat Hunting Agent. Extract the technique details. Output a JSON object with 'id' (external ID), 'name' (technique name), 'details' (description). Return {} if not an attack-pattern."
    return _execute_specialist(raw_items, prompt, "attack")

def run_capec_agent(raw_items):
    """Agent specifically dedicated to CAPEC Attack Patterns."""
    prompt = "You are an Application Security Expert analyzing CAPEC data. Extract the exploit mechanics. Output a JSON object with 'id' (CAPEC ID), 'name' (attack name), 'details' (description). Return {} if invalid."
    return _execute_specialist(raw_items, prompt, "capec")


# ==========================================
# NORMALIZING LAYER: ONE CENTRAL AGENT
# ==========================================

def run_central_normalizer(specialist_outputs):
    """
    The Central Normalization Agent.
    Takes input from the 5 Source Agents and formats it for the DB.
    """
    prompt = """
    You are the Central Data Normalizer.
    Input: A semi-structured JSON object from a specialist agent.
    Task: Map it strictly to the database schema.
    Target Schema:
    {
      "source": "nvd", "attack", "capec", "pypi", or "github",
      "record_type": "cve", "attack-pattern", "package", or "advisory",
      "canonical_id": "ID String (e.g., CVE-XXXX, TXXXX, CAPEC-XXX, package name)",
      "title": "Short title",
      "summary": "Short description (max 1 sentence)",
      "severity": "HIGH/MEDIUM/LOW or null",
      "published_at": "ISO Date or null",
      "references": []
    }
    Output: ONLY the JSON object.
    """
    
    print(f"    [Normalizer Agent] Processing {len(specialist_outputs)} items from specialists...")
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