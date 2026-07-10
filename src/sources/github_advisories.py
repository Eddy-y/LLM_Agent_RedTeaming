"""
sources/github_advisories.py

Uses GitHub GraphQL API to search security advisories by ecosystem and package.
CORRECTED: Uses securityVulnerabilities instead of securityAdvisories to allow filtering.

This requires a GitHub token:
  export GITHUB_TOKEN="..."
"""

from __future__ import annotations

from typing import Any
import time
from datetime import datetime, timezone

import requests
from tenacity import retry, wait_exponential, stop_after_attempt

def utc_now_iso() -> str:
    """Returns current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


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
    start_page: int = 0,
    max_items: int = 20,
) -> tuple[int | None, dict[str, Any] | None, str | None, str]:
    """
    Paginates through vulnerabilities and extracts the unique advisories.
    NEW: Supports incremental fetching by starting from a specific page and limiting items.
    """
    endpoint = GRAPHQL_ENDPOINT
    headers = {
        "Authorization": f"Bearer {github_token}",
        "User-Agent": user_agent,
    }

    query = _build_query()
    after = None
    unique_advisories: dict[str, dict] = {}
    current_page = 0
    items_fetched = 0
    has_next_page = False

    try:
        # Pagination loop with item limit
        while items_fetched < max_items:
            variables = {
                "ecosystem": "PIP",
                "package": package,
                "first": page_size,
                "after": after,
            }

            # Rate limiting (skip on first request)
            if current_page > 0:
                time.sleep(2)

            resp = requests.post(
                endpoint,
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=timeout_seconds,
            )
            status = resp.status_code

            # Log detailed error for rate limit and other failures
            if status != 200:
                try:
                    error_body = resp.json()
                    error_msg = error_body.get("message", resp.text[:200])
                except Exception:
                    error_msg = resp.text[:200]

                print(f"    [WARN] GitHub API error (HTTP {status}): {error_msg}")

                # GitHub specific rate limit (403) and standard errors
                if status in [403, 429, 500, 502, 503, 504]:
                    resp.raise_for_status()

                return status, None, f"GitHub GraphQL returned status {status}: {error_msg}", endpoint

            data = resp.json()
            if "errors" in data:
                error_details = data['errors']
                print(f"    [WARN] GitHub GraphQL errors: {error_details}")
                return status, data, f"GitHub GraphQL errors: {error_details}", endpoint

            vuln_data = (((data.get("data") or {}).get("securityVulnerabilities") or {}))
            nodes = vuln_data.get("nodes") or []

            # Only process if we've reached the start_page
            if current_page >= start_page:
                for node in nodes:
                    advisory = node.get("advisory")
                    if advisory:
                        ghsa_id = advisory.get("ghsaId")
                        if ghsa_id and ghsa_id not in unique_advisories:
                            unique_advisories[ghsa_id] = advisory
                            items_fetched += 1
                            if items_fetched >= max_items:
                                break

            page_info = vuln_data.get("pageInfo") or {}
            has_next_page = page_info.get("hasNextPage", False)

            if not has_next_page:
                break

            after = page_info.get("endCursor")
            current_page += 1

        payload = {
            "package": package,
            "nodes": list(unique_advisories.values()),
            "_pagination_meta": {
                "start_page": start_page,
                "items_fetched": items_fetched,
                "last_page_reached": current_page,
                "has_more_pages": has_next_page
            }
        }
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
