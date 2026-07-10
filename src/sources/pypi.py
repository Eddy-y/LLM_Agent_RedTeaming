"""
sources/pypi.py

Fetches package metadata from the PyPI JSON API.

Endpoint:
  https://pypi.org/pypi/{package}/json

This does NOT directly list vulnerabilities.
But it provides:
  package name, version info, project urls, release history
Which is useful enrichment and helps cross linking.

We still store it as raw data and extract a single metadata item record.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone

import requests
from tenacity import retry, wait_exponential, stop_after_attempt

def utc_now_iso() -> str:
    """Returns current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


PYPI_SOURCE = "pypi"

@retry(wait=wait_exponential(multiplier=2, min=4, max=10), stop=stop_after_attempt(3))
def fetch_pypi_json(
    package: str,
    *,
    timeout_seconds: int,
    user_agent: str,
) -> tuple[int | None, dict[str, Any] | None, str | None, str]:
    """
    Returns:
      http_status
      payload if success else None
      error message if any
      endpoint url
    """
    endpoint = f"https://pypi.org/pypi/{package}/json"
    headers = {"User-Agent": user_agent}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=timeout_seconds)
        status = resp.status_code
        
        # Trigger tenacity retry for rate limits and server errors
        if status in [429, 500, 502, 503, 504]:
            resp.raise_for_status() 
            
        if status != 200:
            return status, None, f"PyPI returned status {status}", endpoint
        return status, resp.json(), None, endpoint
        
    except requests.exceptions.HTTPError as e:
        # Re-raise so tenacity can catch the specific HTTP errors we defined above
        if e.response.status_code in [429, 500, 502, 503, 504]:
            raise
        return e.response.status_code, None, f"PyPI HTTP error: {e}", endpoint
    except Exception as e:
        return None, None, f"PyPI request failed: {e}", endpoint


def extract_pypi_item(package: str, raw_path: str, payload: dict[str, Any], run_id: str) -> dict[str, Any]:
    """
    Creates one extracted item representing package metadata.
    Your partner can later use this as context during normalization if needed.
    """
    info = payload.get("info", {}) or {}
    project_urls = info.get("project_urls") or {}
    home_page = info.get("home_page") or ""
    package_url = f"https://pypi.org/project/{package}/"

    return {
        "run_id": run_id,
        "package_name": package,
        "source": PYPI_SOURCE,
        "item_type": "metadata",
        "item_id": info.get("name") or package,
        "title": info.get("summary") or f"{package} metadata",
        "url": home_page or project_urls.get("Homepage") or package_url,
        "published_at": None,
        "severity": None,
        "raw_path": raw_path,
        "extracted_at_utc": utc_now_iso(),
    }
    