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

CRITICAL: The "details" field must be a COMPLETE, ACTIONABLE summary (50-150 words) including:
- Attack vector (how it's exploited)
- Technical impact (what can attackers do?)
- Affected versions (specific ranges)
- Root cause (underlying weakness)

BAD: "Django XSS vulnerability" (too short, 3 words)
GOOD: "Django versions 3.2.0 through 3.2.20 contain a reflected cross-site scripting (XSS) vulnerability in the AdminURLFieldWidget when rendering URLs that contain certain special characters. The widget fails to properly escape user-supplied input in the admin interface, allowing authenticated admin users to inject malicious JavaScript via crafted URL values in model fields. While exploitation requires admin privileges, it can be used to steal session cookies or perform actions as other admin users. Fixed in Django 3.2.21 by implementing proper HTML entity encoding."

REQUIRED FIELDS:
- id: Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx")
- details: DETAILED summary (50-150 words with attack vector, impact, versions, root cause)
- severity: CVSS severity level
- published_at: Publication date (ISO format)
- references: List of reference URLs
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. GHSA → EXPLOITS → CWE (if CWE-* in "identifiers" array)
2. GHSA → AFFECTS → Package (if package in "vulnerabilities.nodes")

EXAMPLE OUTPUT:
{{
  "id": "GHSA-abcd-1234-efgh",
  "details": "Cross-site scripting vulnerability in Django's URLValidator allows remote attackers to inject malicious JavaScript through specially crafted URLs in form inputs. The validator fails to properly sanitize URLs containing JavaScript protocol handlers (e.g., javascript:alert(1)). Attackers can exploit this by submitting forms with malicious URLs, which are then rendered without escaping in templates. Affects Django 4.2 through 4.2.10 when URLValidator is used with user-supplied input. Fixed in 4.2.11 by implementing strict protocol validation and output encoding.",
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
      "properties": {{"version_range": ">=4.2.0,<4.2.11"}}
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- ONLY extract CWE if in "identifiers" array
- ONLY extract package from "vulnerabilities.nodes[].package.name"
- DO NOT invent technical details not in advisory
- Expand short summaries using advisory description + severity + affected versions

OUTPUT: Valid JSON with detailed "details" field (50-150 words)."""
    return _execute_specialist(raw_items, prompt, "github")
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
    prompt = """Extract MITRE ATT&CK technique details AND relationship triples.

CRITICAL: The "details" field must be a COMPLETE tactical description (50-150 words) including:
- What the technique does (adversary action)
- How it's executed (tools, methods, prerequisites)
- What it achieves (tactical advantage)
- Common platforms/targets

BAD: "Process injection technique" (3 words, too vague)
GOOD: "Process Injection (T1055) allows adversaries to execute arbitrary code in the address space of a separate live process. Attackers use this technique to evade defenses by hiding malicious code within legitimate processes, making detection difficult. Common methods include DLL injection, thread execution hijacking, and process hollowing. Requires existing code execution on the target system but enables privilege escalation, defense evasion, and persistence. Commonly targets Windows processes like explorer.exe, svchost.exe, or browser processes. Detection requires monitoring for suspicious cross-process memory operations and abnormal process behaviors."

REQUIRED FIELDS:
- id: External ID from external_references where source_name='mitre-attack' (e.g., "T1055.011")
- name: Technique name
- details: DETAILED tactical description (50-150 words with action, execution, advantage, targets)
- published_at: Creation timestamp (from 'created' field)
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. Sub-technique → SUB_TECHNIQUE_OF → Parent (if ID has dot)
2. Technique → IMPLEMENTS → CAPEC (if CAPEC-* in "external_references")

EXAMPLE OUTPUT:
{{
  "id": "T1055.011",
  "name": "Process Injection: Extra Window Memory Injection",
  "details": "Extra Window Memory Injection is a process injection technique where adversaries inject malicious code into GUI window objects. Attackers exploit the SetWindowLong and GetWindowLong Windows API functions to write and execute code in the extra window memory allocated for window objects. This technique allows code execution within the context of another process without creating new threads or loading DLLs, making it stealthier than traditional injection methods. Requires existing code execution privileges and primarily targets Windows GUI applications. Difficult to detect as it doesn't trigger typical injection detection mechanisms.",
  "published_at": "2020-03-11T14:54:22.800Z",
  "relationships": [
    {{
      "subject": "T1055.011",
      "subject_type": "AttackTactic",
      "predicate": "SUB_TECHNIQUE_OF",
      "object": "T1055",
      "object_type": "AttackTactic"
    }}
  ]
}}

ANTI-HALLUCINATION RULES:
- For sub-techniques: parent = everything before the dot
- ONLY extract CAPEC if in "external_references"
- DO NOT invent tactical details not in description

OUTPUT: Valid JSON with detailed "details" field. The 'id' MUST be external_id (T####), NOT STIX ID."""
    return _execute_specialist(raw_items, prompt, "attack")

def run_capec_agent(raw_items):
    prompt = """Extract CAPEC attack pattern details AND relationship triples.

CRITICAL: The "details" field must be a COMPLETE attack pattern description (50-150 words) including:
- Attack method (how the attacker proceeds)
- Prerequisites (what attacker needs)
- Typical impact (consequences)
- Target weaknesses (what vulnerability enables this)

BAD: "SQL injection attack pattern" (4 words)
GOOD: "SQL Injection (CAPEC-66) exploits improper neutralization of special elements in SQL queries (CWE-89). Attackers inject malicious SQL code through user input fields, URL parameters, or HTTP headers that are directly concatenated into database queries without proper validation or parameterization. Successful attacks allow unauthorized database access, data exfiltration, modification of records, or complete database server compromise. Prerequisites include an application that constructs SQL queries from user input and insufficient input validation. Common targets are web applications with login forms, search functions, or dynamic content rendering that queries databases."

REQUIRED FIELDS:
- id: External ID from external_references where source_name='capec' (e.g., "CAPEC-1")
- name: Pattern name
- details: DETAILED attack pattern (50-150 words with method, prerequisites, impact, targets)
- severity: Extract from 'x_capec_typical_severity' (High/Medium/Low)
- published_at: Creation timestamp (from 'created' field)
- references: List of reference URLs
- relationships: Array of relationship objects (REQUIRED - use empty array if none found)

RELATIONSHIP EXTRACTION:
1. CAPEC → TARGETS → CWE (if in "x_capec_related_weaknesses")
2. CAPEC → CHILD_OF → Parent CAPEC (if in hierarchy)

EXAMPLE OUTPUT:
{{
  "id": "CAPEC-66",
  "name": "SQL Injection",
  "details": "SQL Injection exploits inadequate input validation in database-driven applications. Attackers insert malicious SQL syntax into user input fields that are directly incorporated into SQL queries. This allows manipulation of query logic to bypass authentication, extract sensitive data, modify records, or execute administrative operations. Prerequisites include an application that dynamically constructs SQL queries from user input and lacks proper parameterization or input sanitization. Common vectors are web form fields, URL parameters, and HTTP headers. Impact ranges from data theft to complete database compromise.",
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
- ONLY extract CWE if in "x_capec_related_weaknesses"
- ONLY extract parent if in hierarchy fields
- DO NOT invent attack steps not in source

OUTPUT: Valid JSON with detailed "details" field. 'id' MUST be external_id (CAPEC-#), NOT STIX ID."""
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