"""
sources/nvd.py

Fetches CVE records from the NVD API.

Endpoint (CVE 2.0 API):
  https://services.nvd.nist.gov/rest/json/cves/2.0

We query by keywordSearch using the package name.
This is a heuristic, but good enough for a proof of concept.

Optional NVD_API_KEY increases rate limits.
"""

from __future__ import annotations

from typing import Any

import requests

from ..utils import utc_now_iso


NVD_SOURCE = "nvd"


def fetch_nvd_cves(
    package: str,
    *,
    api_key: str | None,
    timeout_seconds: int,
    user_agent: str,
    results_per_page: int = 10,
) -> tuple[int | None, dict[str, Any] | None, str | None, str]:
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": user_agent}
    if api_key:
        headers["apiKey"] = api_key
        

    params = {
        "keywordSearch": package,
        "resultsPerPage": results_per_page,
        # You can add additional filters later if you want
    }

    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=timeout_seconds)
        status = resp.status_code
        if status != 200:
            return status, None, f"NVD returned status {status}: {resp.text[:200]}", endpoint
        return status, resp.json(), None, endpoint
    except Exception as e:
        return None, None, f"NVD request failed: {e}", endpoint


def extract_nvd_items(package: str, raw_path: str, payload: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    """
    Extracts a minimal CVE level view from NVD payload.

    NVD structure can be nested, so we carefully access keys.
    """
    items: list[dict[str, Any]] = []
    vulns = payload.get("vulnerabilities") or []

    for v in vulns:
        cve = (v.get("cve") or {})
        cve_id = cve.get("id")

        # Description is a list of localized objects, we prefer English
        desc = ""
        descriptions = cve.get("descriptions") or []
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value") or ""
                break

        # Try to extract a CVSS base score if present
        score = None
        severity = None
        metrics = cve.get("metrics") or {}

        # CVSS v3.1 is common, but not always present
        cvss_v31 = metrics.get("cvssMetricV31") or []
        if cvss_v31 and isinstance(cvss_v31, list):
            metric = cvss_v31[0] or {}
            cvss_data = (metric.get("cvssData") or {})
            score = cvss_data.get("baseScore")
            severity = (cvss_data.get("baseSeverity") or "").lower() or None

        # Link to NVD detail page for the CVE
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None

        items.append(
            {
                "run_id": run_id,
                "package_name": package,
                "source": NVD_SOURCE,
                "item_type": "cve",
                "item_id": cve_id,
                "title": desc[:250] if desc else None,
                "url": url,
                "published_at": cve.get("published"),
                "severity": severity,
                "raw_path": raw_path,
                "extracted_at_utc": utc_now_iso(),
            }
        )

    return items
