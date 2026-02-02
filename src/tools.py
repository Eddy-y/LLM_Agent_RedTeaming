from langchain.tools import tool
from src.sources.pypi import fetch_pypi_json
from src.sources.github_advisories import fetch_github_advisories
from src.sources.nvd import fetch_nvd_cves
from src.utils import safe_slug, utc_now_iso

# Helper to handle the "messy" data before the LLM sees it
def simplify_payload(payload, source_type):
    """Reduces 500 lines of JSON to the key security facts."""
    if not payload:
        return "No data found."
    
    # Example logic - customize based on what your 'Collector' agent usually looks for
    if source_type == "pypi":
        info = payload.get('info', {})
        return f"Summary: {info.get('summary')}\nVersion: {info.get('version')}\nAuthor: {info.get('author')}"
    
    # For Lists (GitHub/NVD), just return counts or top items to save tokens
    if isinstance(payload, list):
        return f"Found {len(payload)} records. Top item: {str(payload[0])[:200]}..."
        
    return str(payload)[:500] + "..." # Truncate to protect context window

@tool
def check_pypi_metadata(package_name: str) -> str:
    """
    Fetches package metadata from PyPI. 
    Use this to verify if a package exists and get its summary/author info.
    """
    # Reuse your existing logic
    status, payload, error, _ = fetch_pypi_json(package_name)
    
    if status != 200:
        return f"Error fetching PyPI: {error}"
    
    return simplify_payload(payload, "pypi")

@tool
def check_github_advisories(package_name: str) -> str:
    """
    Queries GitHub Security Advisories for known vulnerabilities.
    Use this if you suspect the package has reported security issues.
    """
    # Note: Requires GITHUB_TOKEN to be set in environment
    # You might need to import settings here to access the token
    from src.config import get_settings
    settings = get_settings()
    
    status, payload, error, _ = fetch_github_advisories(
        package_name, 
        github_token=settings.github_token
    )
    
    if status != 200:
        return f"Error fetching GitHub: {error}"
        
    return simplify_payload(payload, "github")

@tool
def check_nvd_cves(package_name: str) -> str:
    """
    Searches the National Vulnerability Database (NVD) for CVEs.
    Use this as a fallback if GitHub Advisories are empty or strictly for CVE lookups.
    """
    from src.config import get_settings
    settings = get_settings()

    status, payload, error, _ = fetch_nvd_cves(
        package_name,
        api_key=settings.nvd_api_key
    )
    
    if status != 200:
        return f"Error fetching NVD: {error}"
        
    return simplify_payload(payload, "nvd")

# List of tools to bind to the model
search_tools = [check_pypi_metadata, check_github_advisories, check_nvd_cves]