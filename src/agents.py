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

def query_bedrock(prompt, data_snippet, agent_name="Unknown Agent", file_origin="src/agents.py", max_tokens=512):
    content = f"{prompt}\n\nDATA SNIPPET:\n{json.dumps(data_snippet)[:2000]}"
    payload = {
        "prompt": f"<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n{content}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
        "max_gen_len": max_tokens, "temperature": 0.1, "top_p": 0.9
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

def _execute_specialist(raw_items, prompt, source_name, max_tokens=512):
    candidates = []
    for idx, item in enumerate(raw_items):
        result = query_bedrock(prompt, item, agent_name=f"{source_name.upper()} Specialist", max_tokens=max_tokens)
        if result and result.get("id"):
            result["_origin_source"] = source_name
            candidates.append(result)
        else:
            # Enhanced logging to debug LLM extraction failures
            print(f"[DROP] Item {idx+1} from {source_name}:")
            print(f"  LLM returned: {json.dumps(result, indent=2)}")
            # Show first 500 chars of input data to diagnose
            input_preview = json.dumps(item, indent=2)[:500]
            print(f"  Input data preview: {input_preview}...")
    return candidates

def run_pypi_agent(raw_items):
    prompt = """Extract the vulnerability id (use package name if no CVE exists), detailed description, severity, and published date. 
    You MUST output ONLY a valid JSON object using exactly these keys: {"id": "...", "details": "...", "severity": "...", "published_at": "..."}"""
    return _execute_specialist(raw_items, prompt, "pypi")
def run_github_agent(raw_items):
    # Filter out withdrawn/duplicate advisories before processing
    active_items = [
        item for item in raw_items
        if not ("Duplicate Advisory" in item.get("summary", "") or
                "withdrawn" in item.get("summary", "").lower() or
                item.get("withdrawnAt"))
    ]

    if len(active_items) < len(raw_items):
        print(f"    [FILTER] Skipped {len(raw_items) - len(active_items)} withdrawn/duplicate GitHub advisories")

    prompt = """Extract GitHub Security Advisory details. Output ONLY valid JSON.

REQUIRED FIELDS:
- id: Advisory ID from "ghsaId" field (e.g., "GHSA-xxxx-xxxx-xxxx")
- details: DETAILED summary (50-150 words) - combine "summary" + "description" fields with attack vector, impact, affected versions
- severity: From "severity" field (CRITICAL/HIGH/MEDIUM/LOW)
- published_at: From "publishedAt" field (ISO format)
- references: Array of reference URLs (use ["https://github.com/advisories/{ghsaId}"] if none)
- relationships: Empty array [] for now

EXAMPLE:
{{
  "id": "GHSA-abcd-1234-efgh",
  "details": "Django URLValidator XSS vulnerability allows JavaScript injection via crafted URLs. Affects Django 4.2.0-4.2.10. Fixed in 4.2.11.",
  "severity": "MEDIUM",
  "published_at": "2024-01-15T00:00:00Z",
  "references": ["https://github.com/advisories/GHSA-abcd-1234-efgh"],
  "relationships": []
}}

OUTPUT: Valid JSON only, no explanatory text."""
    return _execute_specialist(active_items, prompt, "github", max_tokens=1024)
def run_nvd_agent(raw_items, package_name):
    prompt = f"""Extract CVE details AND relationship triples for Python package '{package_name}'.

CRITICAL: The "details" field must be a COMPLETE, ACTIONABLE summary (50-150 words) including:
- Attack vector (how it's exploited: network, local, requires auth?)
- Technical impact (RCE, data leak, DoS, privilege escalation?)
- Affected versions (specific version ranges if available)
- Root cause (buffer overflow, injection, deserialization, etc.)

BAD EXAMPLE: "Flask session vulnerability allows unauthorized access" (too vague, 6 words)
GOOD EXAMPLE: "Vulnerable versions of Flask (2.0.1-2.3.0) may send one client's session cookie to other clients when the application is hosted behind a caching proxy that does not include the Vary: Cookie header. This occurs because Flask's session handling does not explicitly set the Vary header, allowing proxies to serve cached responses with embedded session cookies to different users. Attackers can exploit this to hijack authenticated sessions without credentials, leading to unauthorized account access and data exposure. Requires specific proxy configuration but no authentication."

REQUIRED FIELDS:
- id: CVE identifier (e.g., "CVE-2023-1234")
- details: DETAILED summary (50-150 words, see above requirements)
- severity: CVSS severity level (CRITICAL/HIGH/MEDIUM/LOW)
- published_at: Publication date (ISO format)
- references: List of reference URLs
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. CVE → EXPLOITS → CWE (if CWE-* in "weaknesses" field)
2. CVE → AFFECTS → Package (if "{package_name}" mentioned)

EXAMPLE OUTPUT:
{{
  "id": "CVE-2024-1234",
  "details": "SQL injection vulnerability in Flask-Admin before version 1.6.0 allows remote authenticated users to execute arbitrary SQL queries via crafted input in the model list view filters. The vulnerability exists in the apply_filters method which directly concatenates user input into SQL WHERE clauses without proper parameterization. Successful exploitation allows attackers to bypass authorization controls, extract sensitive data from the database, or modify records. Requires valid user credentials but no additional privileges. Fixed in version 1.6.0 by implementing parameterized queries.",
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
      "properties": {{"version_range": ">=1.0.0,<1.6.0"}}
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE if in "weaknesses" field
- ONLY add AFFECTS if "{package_name}" mentioned
- DO NOT invent technical details not in the source data
- If description is short, expand with attack vector + impact + fix info from the CVE data

OUTPUT: Valid JSON with detailed "details" field (50-150 words)."""
    return _execute_specialist(raw_items, prompt, "nvd")
def run_mitre_agent(raw_items):
    prompt = """Extract MITRE ATT&CK technique. Output ONLY valid JSON.

REQUIRED FIELDS:
- id: External ID from external_references where source_name='mitre-attack' (e.g., "T1055")
- name: Technique name from "name" field
- details: DETAILED description (50-150 words) from "description" field
- published_at: From "created" field (ISO format)
- relationships: Empty array []

EXAMPLE:
{{
  "id": "T1055",
  "name": "Process Injection",
  "details": "Process Injection allows adversaries to execute code in another process's address space. Enables defense evasion and privilege escalation.",
  "published_at": "2020-03-11T14:54:22Z",
  "relationships": []
}}

OUTPUT: Valid JSON only. Extract 'id' from external_references array where source_name='mitre-attack'."""
    return _execute_specialist(raw_items, prompt, "attack", max_tokens=1024)

def run_capec_agent(raw_items):
    prompt = """Extract CAPEC attack pattern. Output ONLY valid JSON.

REQUIRED FIELDS:
- id: External ID from external_references where source_name='capec' (e.g., "CAPEC-100")
- name: Pattern name from "name" field
- details: DETAILED description (50-150 words) from "description" field
- severity: From 'x_capec_typical_severity' field (High/Medium/Low)
- published_at: From "created" field (ISO format)
- references: Construct as ["https://capec.mitre.org/data/definitions/{id_number}.html"]
- relationships: Empty array []

EXAMPLE:
{{
  "id": "CAPEC-100",
  "name": "Overflow Buffers",
  "details": "Buffer overflow attacks target improper bounds checking. Attackers inject input exceeding buffer limits.",
  "severity": "High",
  "published_at": "2014-06-23T00:00:00Z",
  "references": ["https://capec.mitre.org/data/definitions/100.html"],
  "relationships": []
}}

OUTPUT: Valid JSON only."""
    return _execute_specialist(raw_items, prompt, "capec", max_tokens=1024)

def run_exploitdb_agent(raw_items):
    prompt = """Extract Exploit-DB exploit details. Be lenient - extract what you can from limited data.

REQUIRED FIELDS:
- id: EDB-ID from "id" field (format: "EDB-12345" where 12345 is the id value)
- details: Expand the description into 30-100 words. If description is short, add context based on exploit type/platform. Focus on vulnerability type, attack method, and impact.
- severity: Infer from type (remote=CRITICAL, local=HIGH, dos=MEDIUM, webapps=HIGH)
- published_at: Use "date" field if present, otherwise use "2020-01-01T00:00:00Z" as default
- references: Array with exploit URL ["https://www.exploit-db.com/exploits/{id}"] where {id} is the numeric id
- relationships: Array of relationship objects (can be empty array [] if no clear relationships)

RELATIONSHIP RULES (OPTIONAL - only add if applicable):
1. Add DEMONSTRATES relationship ONLY if verified_cves array has CVE IDs
2. Add AFFECTS relationship if you can identify affected software from description
3. Leave relationships array empty [] if uncertain

SEVERITY INFERENCE:
- type="remote" → CRITICAL
- type="local" → HIGH
- type="dos" → MEDIUM
- type="webapps" → HIGH

EXAMPLE 1 (with CVE):
{{
  "id": "EDB-51234",
  "details": "Buffer overflow vulnerability in MOV Converter allows local attacker to execute arbitrary code via crafted filename. Exploits improper input validation in file parsing routine. Successful exploitation grants code execution privileges.",
  "severity": "HIGH",
  "published_at": "2018-12-15T00:00:00Z",
  "references": ["https://www.exploit-db.com/exploits/51234"],
  "relationships": [
    {{
      "subject": "EDB-51234",
      "subject_type": "Exploit",
      "predicate": "DEMONSTRATES",
      "object": "CVE-2018-1234",
      "object_type": "Vulnerability"
    }}
  ]
}}

EXAMPLE 2 (no CVE, null date):
{{
  "id": "EDB-45101",
  "details": "Local buffer overflow in Allok MOV Converter via malformed filename. Structured Exception Handler (SEH) based exploit allows code execution when processing specially crafted input. Requires user interaction to open malicious file.",
  "severity": "HIGH",
  "published_at": "2020-01-01T00:00:00Z",
  "references": ["https://www.exploit-db.com/exploits/45101"],
  "relationships": []
}}

IMPORTANT: Always return valid JSON. Extract the id field and format as "EDB-{id}". If data is minimal, do your best to expand the description based on type and platform context.

OUTPUT: Valid JSON object with all required fields."""
    return _execute_specialist(raw_items, prompt, "exploitdb", max_tokens=1024)

def run_central_normalizer(specialist_outputs, source_name):
    prompt = f"""Normalize the following threat intelligence data.

    Rules for specific fields:
    - "source": strictly use "{source_name}"
    - "record_type": Infer this from the ID prefix (e.g., use "CVE" if it starts with CVE, "GHSA" if it starts with GHSA, "EDB" if it starts with EDB).
    - "canonical_id": Use the "id" field from input AS-IS (e.g., if id="EDB-12345", then canonical_id="EDB-12345")
    - "title": Generate a concise, 4-to-6 word technical title summarizing the vulnerability based on the description.
    - "summary": Use the "details" field from input as the summary

    Target Schema: {{"source": "...", "record_type": "...", "canonical_id": "...", "title": "...", "summary": "...", "severity": "...", "published_at": "...", "references": ["url1", "url2"]}}

    CRITICAL: The canonical_id field MUST match the id field from input exactly. Do not drop the prefix (keep EDB-, CVE-, GHSA-, etc.).

    Output JSON only."""
    normalized_results = []
    for item in specialist_outputs:
        result = query_bedrock(prompt, item, agent_name="Central Normalizer")
        # Accept both "canonical_id" and "id" (normalize "id" → "canonical_id")
        if result:
            if not result.get("canonical_id") and result.get("id"):
                result["canonical_id"] = result["id"]
            if result.get("canonical_id"):
                normalized_results.append(result)
    return normalized_results