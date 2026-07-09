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

RELATIONSHIP EXTRACTION:
- relationships: Array of relationship triples

Extract these RELATIONSHIP TYPES if present in data:
1. GHSA → AFFECTS → Package (extract package name and version range from "vulnerable_version_range" or "affected" field)
2. GHSA → EXPLOITS → CWE (if CWE-* mentioned in "identifiers" array or description)

RELATIONSHIP SCHEMA:
{{
  "subject": "GHSA-xxxx-xxxx-xxxx",
  "subject_type": "Vulnerability",
  "predicate": "EXPLOITS|AFFECTS",
  "object": "CWE-89|package-name",
  "object_type": "Weakness|Package",
  "properties": {{"version_range": ">=X.Y.Z,<A.B.C"}}  // Only for AFFECTS
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE if present in "identifiers" field or explicitly mentioned
- DO NOT guess version ranges
- If uncertain, omit the relationship

OUTPUT: Valid JSON with keys: {{"id": "...", "details": "...", "severity": "...", "published_at": "...", "references": [...], "relationships": []}}"""
    return _execute_specialist(raw_items, prompt, "github")
def run_nvd_agent(raw_items, package_name):
    prompt = f"""Extract CVE details AND relationship triples for Python package '{package_name}'.

REQUIRED FIELDS:
- id: CVE identifier (e.g., "CVE-2023-1234")
- details: Detailed vulnerability description
- severity: CVSS severity level (CRITICAL/HIGH/MEDIUM/LOW)
- published_at: Publication date (ISO format)
- references: List of reference URLs

RELATIONSHIP EXTRACTION (NEW):
- relationships: Array of relationship triples (see schema below)

Extract these RELATIONSHIP TYPES if explicitly mentioned in the data:
1. CVE → EXPLOITS → CWE (if CWE-* mentioned in "weaknesses" field or description)
2. CVE → AFFECTS → Package (extract package name "{package_name}" and version range from "configurations" field)
3. CVE → ENABLES → MITRE Tactic (if T-* or TA-* mentioned in description or references)

RELATIONSHIP SCHEMA:
{{
  "subject": "CVE-YYYY-NNNNN",
  "subject_type": "Vulnerability",
  "predicate": "EXPLOITS|AFFECTS|ENABLES",
  "object": "CWE-89|package-name|T1055",
  "object_type": "Weakness|Package|AttackTactic",
  "properties": {{"version_range": ">=X.Y.Z,<A.B.C"}}  // Only for AFFECTS predicate
}}

ANTI-HALLUCINATION RULES:
- ONLY extract relationships explicitly stated in the data
- DO NOT infer CWE numbers unless mentioned in "weaknesses" field or description
- DO NOT guess MITRE tactic IDs
- If uncertain, omit the relationship
- Package version ranges MUST be extracted from "configurations" field, not guessed

OUTPUT: Valid JSON with keys: {{"id": "...", "details": "...", "severity": "...", "published_at": "...", "references": ["url1", "url2"], "relationships": [...]}}
If no relationships found, use empty array: "relationships": []"""
    return _execute_specialist(raw_items, prompt, "nvd")
def run_mitre_agent(raw_items):
    prompt = """Extract MITRE ATT&CK technique details AND relationship triples.

REQUIRED FIELDS:
- id: External ID from external_references where source_name='mitre-attack' (e.g., "T1055.011")
- name: Technique name
- details: Description text
- published_at: Creation timestamp (from 'created' field)

RELATIONSHIP EXTRACTION:
- relationships: Array of relationship triples

Extract these RELATIONSHIP TYPES if present:
1. Sub-technique → SUB_TECHNIQUE_OF → Parent Technique (if ID has dot notation like T1055.011 → T1055)
2. Technique → IMPLEMENTS → CAPEC (if CAPEC references exist in "external_references" array)

RELATIONSHIP SCHEMA:
{{
  "subject": "T1055.011",
  "subject_type": "AttackTactic",
  "predicate": "SUB_TECHNIQUE_OF|IMPLEMENTS",
  "object": "T1055|CAPEC-66",
  "object_type": "AttackTactic|AttackPattern"
}}

ANTI-HALLUCINATION RULES:
- For sub-techniques: Extract parent ID by removing everything after the dot (T1055.011 → T1055)
- ONLY extract CAPEC relationships if CAPEC-* appears in "external_references" array
- DO NOT infer relationships

OUTPUT: Valid JSON with keys: {{"id": "T####", "name": "...", "details": "...", "published_at": "...", "relationships": []}}
The 'id' field MUST be the external_id (like T1055.011), NOT the STIX ID."""
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

RELATIONSHIP EXTRACTION:
- relationships: Array of relationship triples

Extract these RELATIONSHIP TYPES if present:
1. CAPEC → TARGETS → CWE (if present in "x_capec_related_weaknesses" or "related_weaknesses" field)
2. CAPEC → CHILD_OF → Parent CAPEC (if present in hierarchy/parent relationship fields)

RELATIONSHIP SCHEMA:
{{
  "subject": "CAPEC-66",
  "subject_type": "AttackPattern",
  "predicate": "TARGETS|CHILD_OF",
  "object": "CWE-89|CAPEC-1",
  "object_type": "Weakness|AttackPattern"
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE relationships if explicitly listed in weakness-related fields
- ONLY extract parent CAPEC if explicitly stated in hierarchy fields
- DO NOT infer or guess relationships

OUTPUT: Valid JSON with keys: {{"id": "CAPEC-#", "name": "...", "details": "...", "severity": "...", "published_at": "...", "references": [...], "relationships": []}}
The 'id' field MUST be the external_id (like CAPEC-1), NOT the STIX ID."""
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