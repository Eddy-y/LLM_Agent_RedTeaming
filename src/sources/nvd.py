"""
sources/nvd.py

Fetches and filters CVE records from the NVD API.
Implements temporal and heuristic filtering to improve RAG retrieval accuracy.
"""

from __future__ import annotations
from typing import Any
import requests
from tenacity import retry, wait_exponential, stop_after_attempt
from ..utils import utc_now_iso

NVD_SOURCE = "nvd"

# RQ1: Logic to prevent temporal hallucinations (e.g., 1999 CVEs for a 2011 library)
PACKAGE_BIRTH_YEARS = {
    "flask": 2010,
    "django": 2005,
    "requests": 2011,
    "pyyaml": 2006,
    "jinja2": 2008
}

@retry(wait=wait_exponential(multiplier=2, min=4, max=15), stop=stop_after_attempt(5))
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

    params = {
        "keywordSearch": f"python {package}", # This blocks Xen 'FLASK' from downloading
        "resultsPerPage": results_per_page,
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
    """
    Extracts CVE details with rigorous filtering for ecosystem relevance.
    """
    items: list[dict[str, Any]] = []
    vulns = payload.get("vulnerabilities") or []

    for v in vulns:
        cve = (v.get("cve") or {})
        cve_id = cve.get("id")
        published_date = cve.get("published", "")

        # --- FILTER 1: Temporal Filtering (RQ1) ---
        if published_date and package.lower() in PACKAGE_BIRTH_YEARS:
            try:
                pub_year = int(published_date.split("-")[0])
                if pub_year < PACKAGE_BIRTH_YEARS[package.lower()]:
                    continue # Discard vulnerabilities older than the library itself
            except (ValueError, IndexError):
                pass

        # Extract Description
        desc = ""
        descriptions = cve.get("descriptions") or []
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value") or ""
                break

        # --- FILTER 2: Heuristic Context Filtering ---
        # Discard records involving unrelated architectures (Xen, Kernel, Hardware)
        desc_lower = desc.lower()
        if any(term in desc_lower for term in ["xen ", "hypervisor", "kernel", "hardware", "firmware", "cisco"]):
            if "python" not in desc_lower and "flask" in desc_lower:
                # Double check to ensure we aren't filtering out valid Python/Flask bugs
                continue

        # Extract Metrics
        severity = None
        metrics = cve.get("metrics") or {}
        cvss_v31 = metrics.get("cvssMetricV31") or []
        if cvss_v31 and isinstance(cvss_v31, list):
            metric = cvss_v31[0] or {}
            cvss_data = (metric.get("cvssData") or {})
            severity = (cvss_data.get("baseSeverity") or "").upper() or None

        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None

        items.append({
            "run_id": run_id,
            "package_name": package,
            "source": NVD_SOURCE,
            "item_type": "cve",
            "item_id": cve_id,
            "title": desc[:250] if desc else None,
            "url": url,
            "published_at": published_date,
            "severity": severity,
            "raw_path": raw_path,
            "extracted_at_utc": utc_now_iso(),
        })

    return items
