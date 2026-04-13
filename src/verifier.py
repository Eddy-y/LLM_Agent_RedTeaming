import json
import requests
from pathlib import Path
from datetime import datetime
from .url_validator import validate_text_urls
from .config import OLLAMA_URL, OLLAMA_MODEL # Assuming these are exported in config

AUDIT_LOG_FILE = Path("data/audit_logs.jsonl")

def run_verification_and_log(agent_name: str, file_origin: str, context: str, response: str):
    """
    Passively evaluates an agent's response for hallucinations and broken URLs,
    then logs the insights without modifying the workflow.
    """
    # 1. URL Validation
    url_insights = validate_text_urls(response)
    
    # 2. Hallucination Check via LLM
    judge_prompt = f"""
    You are a strict AI Auditor.
    Compare the provided SOURCE_CONTEXT against the AGENT_RESPONSE.
    Did the agent hallucinate, fabricate, or include any facts/IDs not present in the SOURCE_CONTEXT?
    
    SOURCE_CONTEXT: {str(context)[:2000]}
    
    AGENT_RESPONSE: {str(response)}
    
    Respond ONLY with a JSON object in this exact format:
    {{"hallucination_detected": true/false, "reason": "brief explanation"}}
    """
    
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "user", "content": judge_prompt}],
        "stream": False,
        "format": "json"
    }
    
    hallucination_result = {"hallucination_detected": False, "reason": "Verification failed"}
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
        if resp.status_code == 200:
            hallucination_result = json.loads(resp.json()["message"]["content"])
    except Exception as e:
        print(f"      [!] Verifier LLM Error: {e}")

    # 3. Log the findings
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "file_origin": file_origin,
        "agent_name": agent_name,
        "evaluation": {
            "hallucination_detected": hallucination_result.get("hallucination_detected", False),
            "hallucination_reason": hallucination_result.get("reason", ""),
            "url_validation": url_insights
        }
    }
    
    # Print a tiny unobtrusive alert in the terminal if something is wrong
    if log_entry["evaluation"]["hallucination_detected"]:
        print(f"\n      ⚠️ [AUDIT WARNING]: Hallucination detected in {agent_name} ({file_origin})")
    if any(not u["is_valid"] for u in url_insights):
        print(f"\n      ⚠️ [AUDIT WARNING]: Broken URL detected in {agent_name} ({file_origin})")

    # Append to JSONL log
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")