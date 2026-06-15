import os
import json
import re
import boto3
from .config import get_settings
from botocore.exceptions import ClientError

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
    prompt = """Extract the advisory id, detailed description, severity level (CVSS), published date, and a list of reference URLs. 
    You MUST output ONLY a valid JSON object using exactly these keys: {"id": "...", "details": "...", "severity": "...", "published_at": "...", "references": ["url1", "url2"]}"""
    return _execute_specialist(raw_items, prompt, "github")
def run_nvd_agent(raw_items, package_name):
    prompt = f"""Extract CVE details for Python package '{package_name}'. Include the id, detailed description, severity level, published date, and a list of reference URLs. 
    You MUST output ONLY a valid JSON object using exactly these keys: {{"id": "...", "details": "...", "severity": "...", "published_at": "...", "references": ["url1", "url2"]}}"""
    return _execute_specialist(raw_items, prompt, "nvd")
def run_mitre_agent(raw_items):
    return _execute_specialist(raw_items, "Extract id, name, details. Output JSON only.", "attack")
def run_capec_agent(raw_items):
    return _execute_specialist(raw_items, "Extract CAPEC details. You MUST include an 'id' key representing the CAPEC ID. Output JSON only.", "capec")

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