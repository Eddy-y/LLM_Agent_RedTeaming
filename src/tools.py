from langchain.tools import tool
from src.sources.pypi import fetch_pypi_json
from src.sources.github_advisories import fetch_github_advisories
from src.sources.nvd import fetch_nvd_cves
from src.config import get_settings

def simplify_payload(payload, source_type):
    """
    Helper: Reduces massive JSON dumps to the key security facts 
    so the LLM context window doesn't explode.
    """
    if not payload:
        return "No data found."
    
    if source_type == "pypi":
        info = payload.get('info', {})
        return f"Summary: {info.get('summary')}\nVersion: {info.get('version')}\nAuthor: {info.get('author')}"
    
    if isinstance(payload, list):
        # For lists (Github/NVD), return a summary count and the first item
        return f"Found {len(payload)} records. First item: {str(payload[0])[:300]}..."
        
    return str(payload)[:500] + "..."

@tool
def check_pypi_metadata(package_name: str) -> str:
    """
    REQUIRED: package_name (str).
    Fetches metadata for a python package to verify existence and basic info.
    Example: check_pypi_metadata(package_name="flask")
    """
    # 1. Load Settings
    settings = get_settings()
    
    # 2. Pass REQUIRED arguments (timeout & user_agent)
    status, payload, error, _ = fetch_pypi_json(
        package_name,
        timeout_seconds=settings.http_timeout_seconds,
        user_agent=settings.user_agent
    )
    
    if status != 200:
        return f"Error fetching PyPI: {error}"
    return simplify_payload(payload, "pypi")

@tool
def check_github_advisories(package_name: str) -> str:
    """
    REQUIRED: package_name (str).
    Searches GitHub for security advisories.
    Example: check_github_advisories(package_name="flask")
    """
    settings = get_settings()
    
    # Check if token exists to avoid crashing
    token = settings.github_token or ""
    
    status, payload, error, _ = fetch_github_advisories(
        package_name, 
        github_token=token,
        timeout_seconds=settings.http_timeout_seconds,
        user_agent=settings.user_agent
    )
    if status != 200:
        return f"Error fetching GitHub: {error}"
    return simplify_payload(payload, "github")

@tool
def check_nvd_cves(package_name: str) -> str:
    """
    REQUIRED: package_name (str).
    Searches the National Vulnerability Database (NVD) for CVEs.
    Example: check_nvd_cves(package_name="flask")
    """
    settings = get_settings()
    
    status, payload, error, _ = fetch_nvd_cves(
        package_name, 
        api_key=settings.nvd_api_key,
        timeout_seconds=settings.http_timeout_seconds,
        user_agent=settings.user_agent
    )
    if status != 200:
        return f"Error fetching NVD: {error}"
    return simplify_payload(payload, "nvd")

# Export for run_agents.py
search_tools = [check_pypi_metadata, check_github_advisories, check_nvd_cves]