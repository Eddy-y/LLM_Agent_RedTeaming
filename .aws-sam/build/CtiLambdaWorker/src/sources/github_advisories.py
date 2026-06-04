"""
sources/github_advisories.py

Uses GitHub GraphQL API to search security advisories by ecosystem and package.
CORRECTED: Uses securityVulnerabilities instead of securityAdvisories to allow filtering.

This requires a GitHub token:
  export GITHUB_TOKEN="..."
"""

from __future__ import annotations

from typing import Any

import requests
from tenacity import retry, wait_exponential, stop_after_attempt

from ..utils import utc_now_iso


GITHUB_SOURCE = "github_advisories"
GRAPHQL_ENDPOINT = "https://api.github.com/graphql"


def _build_query() -> str:
    """
    GraphQL query:
      securityVulnerabilities (NOT advisories) allows filtering by package.
      We then grab the 'advisory' object from inside each vulnerability.
    """
    return """
    query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!, $after: String) {
      securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: $first, after: $after) {
        nodes {
          advisory {
            ghsaId
            summary
            description
            severity
            publishedAt
            updatedAt
            references {
              url
            }
            identifiers {
              type
              value
            }
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """

@retry(wait=wait_exponential(multiplier=2, min=4, max=10), stop=stop_after_attempt(3))
def fetch_github_advisories(
    package: str,
    *,
    github_token: str,
    timeout_seconds: int,
    user_agent: str,
    page_size: int = 50,
    max_pages: int = 5,
) -> tuple[int | None, dict[str, Any] | None, str | None, str]:
    """
    Paginates through vulnerabilities and extracts the unique advisories.
    """
    endpoint = GRAPHQL_ENDPOINT
    headers = {
        "Authorization": f"Bearer {github_token}",
        "User-Agent": user_agent,
    }

    query = _build_query()
    after = None
    unique_advisories: dict[str, dict] = {}

    try:
        for _ in range(max_pages):
            variables = {
                "ecosystem": "PIP",
                "package": package,
                "first": page_size,
                "after": after,
            }
            resp = requests.post(
                endpoint,
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=timeout_seconds,
            )
            status = resp.status_code
            
            # GitHub specific rate limit (403) and standard errors
            if status in [403, 429, 500, 502, 503, 504]:
                resp.raise_for_status()

            if status != 200:
                return status, None, f"GitHub GraphQL returned status {status}: {resp.text[:200]}", endpoint

            data = resp.json()
            if "errors" in data:
                return status, data, f"GitHub GraphQL errors: {data['errors']}", endpoint

            vuln_data = (((data.get("data") or {}).get("securityVulnerabilities") or {}))
            nodes = vuln_data.get("nodes") or []
            
            for node in nodes:
                advisory = node.get("advisory")
                if advisory:
                    ghsa_id = advisory.get("ghsaId")
                    if ghsa_id:
                        unique_advisories[ghsa_id] = advisory

            page_info = vuln_data.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")

        payload = {"package": package, "nodes": list(unique_advisories.values())}
        return 200, payload, None, endpoint

    except requests.exceptions.HTTPError as e:
        if e.response.status_code in [403, 429, 500, 502, 503, 504]:
            raise
        return e.response.status_code, None, f"GitHub advisories HTTP error: {e}", endpoint
    except Exception as e:
        return None, None, f"GitHub advisories request failed: {e}", endpoint


def extract_github_items(package: str, raw_path: str, payload: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    """
    Turns GitHub advisory nodes into extracted item rows.
    """
    items: list[dict[str, Any]] = []
    
    for node in payload.get("nodes", []):
        ghsa_id = node.get("ghsaId")
        summary = node.get("summary") or ""
        severity = (node.get("severity") or "").lower() or None

        url = None
        refs = node.get("references") or []
        if refs and isinstance(refs, list):
            url = refs[0].get("url")

        items.append(
            {
                "run_id": run_id,
                "package_name": package,
                "source": GITHUB_SOURCE,
                "item_type": "advisory",
                "item_id": ghsa_id,
                "title": summary[:250] if summary else None,
                "url": url,
                "published_at": node.get("publishedAt"),
                "severity": severity,
                "raw_path": raw_path,
                "extracted_at_utc": utc_now_iso(),
            }
        )

    return items
