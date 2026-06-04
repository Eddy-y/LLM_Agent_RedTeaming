import json
import boto3
from datetime import datetime
from .url_validator import validate_text_urls
from .config import get_settings
from .db import get_db_connection, release_db_connection, log_audit_event

def run_verification_and_log(agent_name: str, file_origin: str, context: str, response: str):
    url_insights = validate_text_urls(response)
    
    judge_prompt = f"""Evaluate for hallucination: SOURCE: {str(context)[:2000]} RESPONSE: {str(response)}. Output JSON: {{"hallucination_detected": bool, "reason": "str"}}"""
    
    settings = get_settings()
    aws_session = boto3.Session(profile_name=settings.aws_profile_name)
    bedrock = aws_session.client('bedrock-runtime', region_name='us-east-1')
    
    hallucination_result = {"hallucination_detected": False, "reason": "Verification failed"}
    
    try:
        payload = {
            "prompt": f"<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n{judge_prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
            "max_gen_len": 200, "temperature": 0.0
        }
        resp = bedrock.invoke_model(
            modelId=settings.bedrock_model_id,
            contentType="application/json", accept="application/json", body=json.dumps(payload)
        )
        response_body = json.loads(resp.get('body').read())
        # Use regex extraction
        import re
        match = re.search(r'\{.*\}', response_body['generation'].replace('\n', ''), re.DOTALL)
        if match:
            hallucination_result = json.loads(match.group(0))
    except Exception as e:
        print(f"      [!] Verifier LLM Error: {e}")

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
    
    # Log directly to RDS
    conn = get_db_connection()
    if conn:
        log_audit_event(conn, log_entry)
        release_db_connection(conn)