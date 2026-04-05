import re
import requests

def extract_urls(text: str) -> list[str]:
    """Extracts all URLs from a given text using regex."""
    url_pattern = re.compile(r'https?://[^\s<>"\']+|(?:www\.[^\s<>"\']+)')
    return url_pattern.findall(str(text))

def check_url_status(url: str, timeout: int = 5) -> dict:
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

def validate_text_urls(text: str) -> list[dict]:
    """Finds and validates all URLs in a text block."""
    urls = extract_urls(text)
    results = []
    # Use a set to avoid checking duplicate URLs
    for url in set(urls):
        results.append(check_url_status(url))
    return results