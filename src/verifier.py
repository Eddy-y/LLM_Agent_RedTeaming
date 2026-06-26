import json
import os
import boto3
import re
from datetime import datetime
from url_validator import validate_text_urls, extract_urls
from config import get_settings
from db import get_db_connection, release_db_connection, log_audit_event

def run_verification_and_log(agent_name: str, file_origin: str, context: str, response: str):
    url_insights = validate_text_urls(response)
    
    judge_prompt = f"""Evaluate for hallucination: SOURCE: {str(context)[:2000]} RESPONSE: {str(response)}. Output ONLY strictly valid JSON: {{"hallucination_detected": false, "reason": "string"}}"""
    
    settings = get_settings()
    profile_name = os.environ.get('AWS_PROFILE') or os.environ.get('AWS_PROFILE_NAME') or 'default'
    
    try:
        # Create a thread-safe session explicitly using the SSO profile
        session = boto3.Session(profile_name=profile_name)
        bedrock = session.client('bedrock-runtime', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    except Exception as auth_err:
        print(f"\n      [!] CRITICAL AWS Auth Error: Could not load SSO profile '{profile_name}'. Did you run 'aws sso login'? Error: {str(auth_err)}\n")
        # Proceed with the failure state so the DB still logs the attempt
        bedrock = None

    hallucination_result = {"hallucination_detected": False, "reason": "Verification failed"}
    
    try:
        payload = {
            "prompt": f"<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n{judge_prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
            "max_gen_len": 300, "temperature": 0.1
        }
        resp = bedrock.invoke_model(
            modelId=settings.bedrock_model_id,
            contentType="application/json", accept="application/json", body=json.dumps(payload)
        )
        response_body = json.loads(resp.get('body').read())
        # Use regex extraction
        
        match = re.search(r'\{.*?\}', response_body['generation'], re.DOTALL)
        if match:
            clean_json_str = match.group(0).replace('True', 'true').replace('False', 'false')
            hallucination_result = json.loads(clean_json_str)
            
    except Exception as e:
        # Print the EXACT error to the terminal so it doesn't fail silently
        print(f"\n      [!] CRITICAL Verifier LLM Error: {str(e)}\n")

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

def validate_and_log_urls(agent_name: str, file_origin: str, response: str):
    """
    Lightweight URL validation without LLM hallucination checking.
    Extracts all URLs from the response, validates each one, and logs results to audit_logs.

    Args:
        agent_name: Name of the agent generating the response
        file_origin: Source file/module where the agent is defined
        response: Text response containing URLs to validate
    """
    # Extract and validate all URLs
    url_validation_results = validate_text_urls(response)

    # Separate valid and invalid URLs for summary
    all_urls = extract_urls(response)
    valid_urls = [r["url"] for r in url_validation_results if r.get("is_valid", False)]
    invalid_urls = [r["url"] for r in url_validation_results if not r.get("is_valid", False)]

    # Build detailed summary
    summary_parts = []
    summary_parts.append(f"Found {len(all_urls)} URL(s) in response")

    if valid_urls:
        summary_parts.append(f"{len(valid_urls)} valid URL(s): {', '.join(valid_urls[:3])}")
        if len(valid_urls) > 3:
            summary_parts.append(f"... and {len(valid_urls) - 3} more")

    if invalid_urls:
        summary_parts.append(f"{len(invalid_urls)} invalid URL(s): {', '.join(invalid_urls[:3])}")
        if len(invalid_urls) > 3:
            summary_parts.append(f"... and {len(invalid_urls) - 3} more")

    if not all_urls:
        summary_parts.append("No URLs detected in response")

    summary = "; ".join(summary_parts)

    # Create log entry matching audit_logs schema
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "file_origin": file_origin,
        "agent_name": agent_name,
        "evaluation": {
            "hallucination_detected": len(invalid_urls) > 0,  # Mark as hallucination if any invalid URLs
            "hallucination_reason": summary,
            "url_validation": url_validation_results
        }
    }

    # Log to RDS
    conn = get_db_connection()
    if conn:
        try:
            log_audit_event(conn, log_entry)
            print(f"    ✓ URL validation logged: {len(valid_urls)} valid, {len(invalid_urls)} invalid")
        except Exception as log_err:
            print(f"    ⚠️ Failed to log URL validation: {log_err}")
        finally:
            release_db_connection(conn)
    else:
        print(f"    ⚠️ DB connection unavailable, skipping audit log")