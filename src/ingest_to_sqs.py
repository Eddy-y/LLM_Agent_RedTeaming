"""
ingest_to_sqs.py
Orchestrates the fetching of raw data from external APIs and pushes it to an AWS SQS queue.
"""

from __future__ import annotations
import boto3
import json
import os
from pathlib import Path
from dotenv import load_dotenv

from .config import get_settings
from .utils import ensure_dir, safe_slug, utc_now_iso, write_json

from .sources.pypi import fetch_pypi_json, PYPI_SOURCE
from .sources.github_advisories import fetch_github_advisories, GITHUB_SOURCE
from .sources.nvd import fetch_nvd_cves, NVD_SOURCE

from .fetchers import fetch_mitre_objects, fetch_capec_objects
from .state import load_state, advance_mitre_offset, advance_capec_offset

# Initialize SQS client
sqs_client = boto3.client('sqs', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
SQS_QUEUE_URL = os.environ.get("SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/CTI-Ingestion-Queue")

def _raw_path_for(data_dir: Path, run_id: str, package: str, source: str) -> Path:
    pkg = safe_slug(package)
    src = safe_slug(source)
    return data_dir / "raw" / run_id / pkg / f"{src}.json"

def push_to_sqs(run_id: str, package: str, source_name: str, raw_items: list):
    """
    Pushes raw fetched items to an AWS SQS Queue for Lambda processing.
    Replaces the old process_payload_with_agents logic.
    """
    if not raw_items:
        return

    print(f"    [SQS] Queuing {len(raw_items)} items for {source_name} processing...")
    
    for item in raw_items:
        message_body = {
            "run_id": run_id,
            "package_target": package,
            "source": source_name,
            "raw_payload": item
        }
        
        sqs_client.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps(message_body)
        )

def run_pipeline(packages: list[str] | None = None) -> str:
    load_dotenv()
    settings = get_settings()

    run_id = safe_slug(utc_now_iso())
    data_dir = settings.data_dir
    ensure_dir(data_dir)

    _run_universal_corpora(run_id)

    if packages is None:
        packages = list(settings.packages)

    for package in packages:
        _run_for_package(run_id, package, settings)

    return run_id
           
def _run_universal_corpora(run_id: str):
    print("\n--- Processing Universal Corpora (MITRE & CAPEC) ---")
    state = load_state()
    
    mitre_offset = state.get("mitre_offset", 0)
    mitre_data = fetch_mitre_objects(offset=mitre_offset, limit=5)
    if mitre_data and mitre_data.get("objects"):
        push_to_sqs(run_id, "Universal", "attack", mitre_data["objects"])
        advance_mitre_offset(5)
        
    capec_offset = state.get("capec_offset", 0)
    capec_data = fetch_capec_objects(offset=capec_offset, limit=5)
    if capec_data and capec_data.get("objects"):
        push_to_sqs(run_id, "Universal", "capec", capec_data["objects"])
        advance_capec_offset(5)

def _run_for_package(run_id: str, package: str, settings) -> None:
    print(f"\nRunning ingestion for package: {package}")

    # Fetch PyPI
    p_status, p_payload, p_err, p_end = fetch_pypi_json(package, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent)
    p_path = _raw_path_for(settings.data_dir, run_id, package, PYPI_SOURCE)
    if p_payload: 
        write_json(p_path, p_payload)
        push_to_sqs(run_id, package, PYPI_SOURCE, [p_payload])

    # Fetch GitHub Advisories
    if settings.github_token:
        gh_status, gh_payload, gh_err, gh_end = fetch_github_advisories(package, github_token=settings.github_token, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent)
        gh_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)
        if gh_payload: 
            write_json(gh_path, gh_payload)
            push_to_sqs(run_id, package, GITHUB_SOURCE, gh_payload)

    # Fetch NVD CVEs
    nvd_status, nvd_payload, nvd_err, nvd_end = fetch_nvd_cves(package, api_key=settings.nvd_api_key, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent)
    nvd_path = _raw_path_for(settings.data_dir, run_id, package, NVD_SOURCE)
    if nvd_payload: 
        write_json(nvd_path, nvd_payload)
        push_to_sqs(run_id, package, NVD_SOURCE, nvd_payload.get("vulnerabilities", []))

if __name__ == "__main__":
    run_id = run_pipeline()
    print(f"\nDone. run_id = {run_id}")