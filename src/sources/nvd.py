"""
sources/nvd.py
Fetches and filters CVE records from the NVD API v2.
Implements rate-limiting compliance and authentic URL mappings for verification.
"""

from __future__ import annotations
import time
from typing import Any
import requests
from tenacity import retry, wait_exponential, stop_after_attempt
from ..utils import utc_now_iso

NVD_SOURCE = "nvd"

PACKAGE_BIRTH_YEARS = {
    "flask": 2010,
    "django": 2005,
    "requests": 2011,
    "pyyaml": 2006,
    "jinja2": 2008,
    "pandas": 2008,
    "numpy": 2006,
    "pytest": 2004
}

@retry(wait=wait_exponential(multiplier=2, min=4, max=15), stop=stop_after_attempt(3))
def fetch_nvd_cves(
    package: str,
    *,
    api_key: str | None,
    timeout_seconds: int,
    user_agent: str,
    results_per_page: int = 20,
) -> tuple[int | None, dict[str, Any] | None, str | None, str]:
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": user_agent}
    
    if api_key:
        headers["apiKey"] = api_key
    else:
        # 🛡️ NIST Compliance Rule: Sleep 6 seconds before every unauthenticated request to prevent 404/429 throttling
        print(f"⏳ Public NVD Mode: Enforcing 6-second cooling window for '{package}'...")
        time.sleep(6)

    # Clean the string value to prevent request malformation
    clean_keyword = str(package).strip().lower()

    params = {
        "keywordSearch": clean_keyword,
        "resultsPerPage": int(results_per_page),
    }

    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=timeout_seconds)
        status = resp.status_code
        
        if status in [403, 429, 500, 502, 503]:
            resp.raise_for_status() 
            
        if status != 200:
            return status, None, f"NVD returned status {status}", endpoint
            
        return status, resp.json(), None, endpoint
    except Exception as e:
        return None, None, f"NVD request failed: {e}", endpoint

def extract_nvd_items(package: str, raw_path: str, payload: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    vulns = payload.get("vulnerabilities") or []

    for v in vulns:
        cve = (v.get("cve") or {})
        cve_id = cve.get("id")
        published_date = cve.get("published", "")

        # --- FILTER 1: Temporal Filtering ---
        if published_date and package.lower() in PACKAGE_BIRTH_YEARS:
            try:
                pub_year = int(published_date.split("-")[0])
                if pub_year < PACKAGE_BIRTH_YEARS[package.lower()]:
                    continue 
            except (ValueError, IndexError):
                pass

        # Extract Description text
        desc = ""
        descriptions = cve.get("descriptions") or []
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value") or ""
                break

        # --- FILTER 2: Heuristic Context Filtering ---
        desc_lower = desc.lower()
        if any(term in desc_lower for term in ["xen ", "hypervisor", "kernel", "hardware", "firmware", "cisco"]):
            if "python" not in desc_lower:
                continue

        # Create authentic, un-hallucinated NIST reference links
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://nvd.nist.gov"

        items.append({
            "run_id": run_id,
            "package_name": package,
            "source": NVD_SOURCE,
            "item_type": "cve",
            "item_id": cve_id,
            "title": desc[:250] if desc else None,
            "url": url, # Pure source URL definition
            "published_at": published_date,
            "severity": None,
            "raw_path": raw_path,
            "extracted_at_utc": utc_now_iso(),
        })

    return items