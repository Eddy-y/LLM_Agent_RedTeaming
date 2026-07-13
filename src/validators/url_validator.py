"""
URL Validator Module

Validates URLs extracted from agent responses by:
1. Extracting all URLs using regex
2. Checking each URL via HTTP HEAD requests
3. Logging validation results to url_validation_logs table

This module replaces the legacy LLM-based hallucination detection approach.
"""

import re
import json
import requests
from datetime import datetime
from typing import List, Dict

from src.config import get_settings
from src.db import get_db_connection, release_db_connection, log_url_validation_event


def extract_urls(text: str) -> List[str]:
    """Extracts all URLs from a given text using regex."""
    url_pattern = re.compile(r'https?://[^\s<>"\']+|(?:www\.[^\s<>"\']+)')
    return url_pattern.findall(str(text))


def check_url_status(url: str, timeout: int = 5) -> Dict[str, any]:
    """Sends a HEAD request to check if the URL is valid (Not 404)."""
    if url.startswith('www.'):
        url = 'http://' + url

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers)

        if response.status_code < 400:
            return {"url": url, "is_valid": True, "status": f"HTTP {response.status_code}"}
        else:
            return {"url": url, "is_valid": False, "status": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"url": url, "is_valid": False, "status": str(e)}


def validate_text_urls(text: str) -> List[Dict[str, any]]:
    """Finds and validates all URLs in a text block."""
    urls = extract_urls(text)
    results = []
    # Use a set to avoid checking duplicate URLs
    for url in set(urls):
        results.append(check_url_status(url))
    return results


def validate_and_log_urls(agent_name: str, file_origin: str, response: str):
    """
    Lightweight URL validation without LLM hallucination checking.
    Extracts all URLs from the response, validates each one, and logs results to url_validation_logs.

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

    # Create log entry matching url_validation_logs schema
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
            log_url_validation_event(conn, log_entry)
            print(f"    ✓ URL validation logged: {len(valid_urls)} valid, {len(invalid_urls)} invalid")
        except Exception as log_err:
            print(f"    ⚠️ Failed to log URL validation: {log_err}")
        finally:
            release_db_connection(conn)
    else:
        print(f"    ⚠️ DB connection unavailable, skipping url validation log")
