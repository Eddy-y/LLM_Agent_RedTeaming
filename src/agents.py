import os
import json
import re
import boto3
from config import get_settings
from botocore.exceptions import ClientError

# Import graph validation function (support both Lambda and local paths)
try:
    from graph_extractor import validate_relationship_triple
except ImportError:
    from src.graph_extractor import validate_relationship_triple

aws_session = boto3.Session(profile_name=get_settings().aws_profile_name)
bedrock_client = aws_session.client('bedrock-runtime', region_name='us-east-1')

def extract_json_from_text(text: str) -> dict:
    """Robustly extracts JSON from LLM output, ignoring conversational wrapper text."""
    try:
        # Match anything between curly braces
        match = re.search(r'\{.*\}', text.replace('\n', ''), re.DOTALL)
        if match:
            return json.loads(match.group(0))
        return {}
    except json.JSONDecodeError:
        return {}

def query_bedrock(prompt, data_snippet, agent_name="Unknown Agent", file_origin="src/agents.py"):
    content = f"{prompt}\n\nDATA SNIPPET:\n{json.dumps(data_snippet)[:2000]}"
    payload = {
        "prompt": f"<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n{content}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
        "max_gen_len": 512, "temperature": 0.1, "top_p": 0.9
    }
    
    try:
        resp = bedrock_client.invoke_model(
            modelId=get_settings().bedrock_model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(payload)
        )
        response_body = json.loads(resp.get('body').read())
        return extract_json_from_text(response_body['generation'])
    except ClientError as e:
        print(f"      [!] AWS Bedrock Error: {e}")
        return {}

def _execute_specialist(raw_items, prompt, source_name):
    candidates = []
    for item in raw_items:
        result = query_bedrock(prompt, item, agent_name=f"{source_name.upper()} Specialist")
        if result and result.get("id"):
            result["_origin_source"] = source_name
            candidates.append(result)
        #Temporally log dropped items for debugging - in production we might want to handle this differently
        else: print(f"Dropped item from {source_name}: {result}")
    return candidates

def run_pypi_agent(raw_items):
    prompt = """Extract the vulnerability id (use package name if no CVE exists), detailed description, severity, and published date. 
    You MUST output ONLY a valid JSON object using exactly these keys: {"id": "...", "details": "...", "severity": "...", "published_at": "..."}"""
    return _execute_specialist(raw_items, prompt, "pypi")
def run_github_agent(raw_items):
    prompt = """Extract GitHub Security Advisory details AND relationship triples.

REQUIRED FIELDS:
- id: Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx")
- details: Detailed description
- severity: CVSS severity level
- published_at: Publication date (ISO format)
- references: List of reference URLs
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. GHSA → EXPLOITS → CWE (if CWE-* in "identifiers" array)
2. GHSA → AFFECTS → Package (if package name in "vulnerabilities" field)

EXAMPLE OUTPUT (copy this structure exactly):
{{
  "id": "GHSA-abcd-1234-efgh",
  "details": "Cross-site scripting vulnerability...",
  "severity": "MEDIUM",
  "published_at": "2024-01-15T00:00:00Z",
  "references": ["https://github.com/advisories/GHSA-abcd-1234-efgh"],
  "relationships": [
    {{
      "subject": "GHSA-abcd-1234-efgh",
      "subject_type": "Vulnerability",
      "predicate": "EXPLOITS",
      "object": "CWE-79",
      "object_type": "Weakness"
    }},
    {{
      "subject": "GHSA-abcd-1234-efgh",
      "subject_type": "Vulnerability",
      "predicate": "AFFECTS",
      "object": "django",
      "object_type": "Package",
      "properties": {{"version_range": ">=2.0,<3.0"}}
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE if "identifiers" array contains {{"type": "CWE", "value": "CWE-##"}}
- ONLY extract package from "vulnerabilities.nodes[].package.name" field
- If no relationships found, output: "relationships": []

OUTPUT: Valid JSON matching the example structure above."""
    return _execute_specialist(raw_items, prompt, "github")
def run_nvd_agent(raw_items, package_name):
    prompt = f"""Extract CVE details AND relationship triples for Python package '{package_name}'.

REQUIRED FIELDS:
- id: CVE identifier (e.g., "CVE-2023-1234")
- details: Detailed vulnerability description
- severity: CVSS severity level (CRITICAL/HIGH/MEDIUM/LOW)
- published_at: Publication date (ISO format)
- references: List of reference URLs
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
Extract these RELATIONSHIP TYPES if explicitly mentioned in the data:
1. CVE → EXPLOITS → CWE (if CWE-* mentioned in "weaknesses" field)
2. CVE → AFFECTS → Package (if package name "{package_name}" appears in data)

EXAMPLE OUTPUT (copy this structure exactly):
{{
  "id": "CVE-2024-1234",
  "details": "SQL injection in Flask application...",
  "severity": "HIGH",
  "published_at": "2024-01-15T00:00:00.000",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
  "relationships": [
    {{
      "subject": "CVE-2024-1234",
      "subject_type": "Vulnerability",
      "predicate": "EXPLOITS",
      "object": "CWE-89",
      "object_type": "Weakness"
    }},
    {{
      "subject": "CVE-2024-1234",
      "subject_type": "Vulnerability",
      "predicate": "AFFECTS",
      "object": "{package_name}",
      "object_type": "Package",
      "properties": {{"version_range": ">=2.0.0,<3.0.0"}}
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE if present in "weaknesses" field (look for "CWE-" pattern)
- ONLY add AFFECTS relationship if package "{package_name}" is mentioned
- DO NOT invent CWE numbers
- If no relationships found, output: "relationships": []

OUTPUT: Valid JSON matching the example structure above."""
    return _execute_specialist(raw_items, prompt, "nvd")
def run_mitre_agent(raw_items):
    prompt = """Extract MITRE ATT&CK technique details AND relationship triples.

REQUIRED FIELDS:
- id: External ID from external_references where source_name='mitre-attack' (e.g., "T1055.011")
- name: Technique name
- details: Description text
- published_at: Creation timestamp (from 'created' field)
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. Sub-technique → SUB_TECHNIQUE_OF → Parent (if ID has dot: T1055.011 → T1055)
2. Technique → IMPLEMENTS → CAPEC (if CAPEC-* in "external_references")

EXAMPLE OUTPUT (copy this structure exactly):
{{
  "id": "T1055.011",
  "name": "Process Injection: Extra Window Memory Injection",
  "details": "Adversaries may inject code into process GUI...",
  "published_at": "2020-03-11T14:54:22.800Z",
  "relationships": [
    {{
      "subject": "T1055.011",
      "subject_type": "AttackTactic",
      "predicate": "SUB_TECHNIQUE_OF",
      "object": "T1055",
      "object_type": "AttackTactic"
    }},
    {{
      "subject": "T1055.011",
      "subject_type": "AttackTactic",
      "predicate": "IMPLEMENTS",
      "object": "CAPEC-66",
      "object_type": "AttackPattern"
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- For sub-techniques (IDs with dots): parent = everything before the dot
- ONLY extract CAPEC if "external_references" contains {{"source_name": "capec", "external_id": "CAPEC-##"}}
- If no relationships, output: "relationships": []

OUTPUT: Valid JSON matching the example. The 'id' MUST be the external_id (T####), NOT the STIX ID."""
    return _execute_specialist(raw_items, prompt, "attack")

def run_capec_agent(raw_items):
    prompt = """Extract CAPEC attack pattern details AND relationship triples.

REQUIRED FIELDS:
- id: External ID from external_references where source_name='capec' (e.g., "CAPEC-1")
- name: Pattern name
- details: Description text
- severity: Extract from 'x_capec_typical_severity' (High/Medium/Low)
- published_at: Creation timestamp (from 'created' field)
- references: List of reference URLs
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. CAPEC → TARGETS → CWE (if in "x_capec_related_weaknesses" field)
2. CAPEC → CHILD_OF → Parent CAPEC (if in hierarchy fields)

EXAMPLE OUTPUT (copy this structure exactly):
{{
  "id": "CAPEC-66",
  "name": "SQL Injection",
  "details": "An attacker exploits...",
  "severity": "High",
  "published_at": "2014-06-23T00:00:00.000Z",
  "references": ["https://capec.mitre.org/data/definitions/66.html"],
  "relationships": [
    {{
      "subject": "CAPEC-66",
      "subject_type": "AttackPattern",
      "predicate": "TARGETS",
      "object": "CWE-89",
      "object_type": "Weakness"
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE if in "x_capec_related_weaknesses" or "related_weaknesses"
- ONLY extract parent if in hierarchy fields
- If no relationships, output: "relationships": []

OUTPUT: Valid JSON matching the example. The 'id' MUST be external_id (CAPEC-#), NOT STIX ID."""
    return _execute_specialist(raw_items, prompt, "capec")

def run_central_normalizer(specialist_outputs, source_name):
    prompt = f"""Normalize the following threat intelligence data. 
    
    Rules for specific fields:
    - "source": strictly use "{source_name}"
    - "record_type": Infer this from the ID prefix (e.g., use "CVE" if it starts with CVE, "GHSA" if it starts with GHSA).
    - "title": Generate a concise, 4-to-6 word technical title summarizing the vulnerability based on the description.
    
    Target Schema: {{"source": "...", "record_type": "...", "canonical_id": "...", "title": "...", "summary": "...", "severity": "...", "published_at": "...", "references": ["url1", "url2"]}} 
    Output JSON only."""
    normalized_results = []
    for item in specialist_outputs:
        result = query_bedrock(prompt, item, agent_name="Central Normalizer")
        if result and result.get("canonical_id"):
            normalized_results.append(result)
    return normalized_results