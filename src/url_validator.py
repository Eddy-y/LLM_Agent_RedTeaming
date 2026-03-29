import re
import requests
from typing import Dict, Any

def extract_urls(text: str) -> list[str]:
    """
    Scans a block of text and extracts all URLs using a regular expression.
    """
    # Regex to capture http and https URLs
    url_pattern = re.compile(r'https?://[^\s<>"\']+|(?:www\.[^\s<>"\']+)')
    return url_pattern.findall(text)

def check_url_status(url: str, timeout: int = 5) -> tuple[bool, str]:
    """
    Sends a HEAD request to the URL to check its HTTP status.
    Returns a tuple: (is_valid_boolean, status_message)
    """
    # Ensure URL has a scheme
    if url.startswith('www.'):
        url = 'http://' + url
        
    try:
        # Use a standard User-Agent, as some security tools block default python-requests
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        
        # A HEAD request is faster as it only fetches headers, not the full page body
        response = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers)
        
        # Consider HTTP 200-399 as valid, 400+ as broken/hallucinated
        if response.status_code < 400:
            return True, f"Valid (HTTP {response.status_code})"
        elif response.status_code == 404:
            return False, "Invalid (HTTP 404 - Not Found)"
        else:
            return False, f"Invalid (HTTP {response.status_code})"
            
    except requests.exceptions.Timeout:
        return False, "Invalid (Connection Timed Out)"
    except requests.exceptions.ConnectionError:
        return False, "Invalid (Connection Error / DNS Failed)"
    except requests.exceptions.RequestException as e:
        return False, f"Invalid (Request Exception: {str(e)})"

def validate_llm_urls(llm_response: str) -> Dict[str, Any]:
    """
    Main function to parse an LLM response, extract URLs, and validate them.
    """
    found_urls = extract_urls(llm_response)
    
    if not found_urls:
        return {"status": "success", "message": "No URLs detected in the response.", "urls": {}}
        
    results = {}
    
    # Use a set to avoid checking the exact same URL multiple times
    for url in set(found_urls):
        is_valid, status_msg = check_url_status(url)
        results[url] = {
            "is_valid": is_valid,
            "status": status_msg
        }
        
    # Determine if any hallucinated/broken URLs were found
    has_broken_urls = any(not data["is_valid"] for data in results.values())
    
    return {
        "status": "warning" if has_broken_urls else "success",
        "message": f"Found {len(results)} unique URL(s). Broken URLs detected!" if has_broken_urls else f"Found {len(results)} unique URL(s). All valid.",
        "urls": results
    }

# --- Example Usage ---
if __name__ == "__main__":
    sample_llm_text = """
    Based on the threat intelligence, here is the report for 'flask'.
    You can read the official docs at https://flask.palletsprojects.com/en/3.0.x/.
    However, there is a known vulnerability detailed here: https://github.com/advisories/GHSA-fake-hallucinated-id-1234
    """
    
    print("Analyzing LLM Response...")
    validation_report = validate_llm_urls(sample_llm_text)
    
    import json
    print(json.dumps(validation_report, indent=4))