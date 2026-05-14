"""
pipeline.py
Orchestrates ingestion for each package and each data source.
Extracts items using Explicit LLM Specialist Agents and Normalizer into unified DB.
"""

from __future__ import annotations
import concurrent.futures
import boto3, json
from pathlib import Path
from typing import Any
from dotenv import load_dotenv

from .config import get_settings
from .db import connect, init_db, insert_fetch_log, insert_normalized_batch
from .utils import ensure_dir, safe_slug, utc_now_iso, write_json

from .sources.pypi import fetch_pypi_json, PYPI_SOURCE
from .sources.github_advisories import fetch_github_advisories, GITHUB_SOURCE
from .sources.nvd import fetch_nvd_cves, NVD_SOURCE

from .fetchers import fetch_mitre_objects, fetch_capec_objects
from .state import load_state, advance_mitre_offset, advance_capec_offset

from .agents import (
    run_pypi_agent, 
    run_github_agent, 
    run_nvd_agent, 
    run_mitre_agent,
    run_capec_agent,
    run_central_normalizer
)

# Initialize SQS client
sqs_client = boto3.client('sqs')
SQS_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/CTI-Ingestion-Queue" # We will create this queue in the AWS Console

def _raw_path_for(data_dir: Path, run_id: str, package: str, source: str) -> Path:
    pkg = safe_slug(package)
    src = safe_slug(source)
    return data_dir / "raw" / run_id / pkg / f"{src}.json"

def process_payload_with_agents(conn, run_id, package, source_name, raw_items, agent_function_name):
    """
    MODIFIED for AWS: Instead of processing locally, push the raw item to an SQS Queue.
    """
    if not raw_items:
        return

    print(f"    [SQS] Queuing {len(raw_items)} items for {source_name} processing...")
    
    for item in raw_items:
        # Package the data into a standard message format
        message_body = {
            "run_id": run_id,
            "package_target": package,
            "source": source_name,
            "raw_payload": item
        }
        
        # Fire and forget to AWS SQS
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

    conn = connect(settings.db_path)
    init_db(conn)

    _run_universal_corpora(conn, run_id)

    if packages is None:
        packages = list(settings.packages)

    for package in packages:
        _run_for_package(conn, run_id, package, settings)

    conn.close()
    return run_id
           
def _run_universal_corpora(conn, run_id):
    print("\n--- Processing Universal Corpora (MITRE & CAPEC) ---")
    state = load_state()
    
    mitre_offset = state.get("mitre_offset", 0)
    mitre_data = fetch_mitre_objects(offset=mitre_offset, limit=5)
    if mitre_data and mitre_data.get("objects"):
        process_payload_with_agents(conn, run_id, "Universal", "attack", mitre_data["objects"], run_mitre_agent)
        advance_mitre_offset(5)
        
    capec_offset = state.get("capec_offset", 0)
    capec_data = fetch_capec_objects(offset=capec_offset, limit=5)
    if capec_data and capec_data.get("objects"):
        process_payload_with_agents(conn, run_id, "Universal", "capec", capec_data["objects"], run_capec_agent)
        advance_capec_offset(5)


def _run_for_package(conn, run_id: str, package: str, settings) -> None:
    print(f"\nRunning ingestion for package: {package}")

    # Launch network I/O concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_pypi = executor.submit(
            fetch_pypi_json, package, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent
        )
        
        future_github = None
        if settings.github_token:
            future_github = executor.submit(
                fetch_github_advisories, package, github_token=settings.github_token, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent
            )
            
        future_nvd = executor.submit(
            fetch_nvd_cves, package, api_key=settings.nvd_api_key, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent
        )

        # Retrieve and process PyPI
        p_status, p_payload, p_err, p_end = future_pypi.result()
        p_path = _raw_path_for(settings.data_dir, run_id, package, PYPI_SOURCE)
        if p_payload: write_json(p_path, p_payload)
        insert_fetch_log(conn, run_id=run_id, package_name=package, source=PYPI_SOURCE, endpoint=p_end, fetched_at_utc=utc_now_iso(), http_status=p_status, error=p_err, raw_path=str(p_path))
        if p_payload: process_payload_with_agents(conn, run_id, package, PYPI_SOURCE, [p_payload], run_pypi_agent)

        # Retrieve and process GitHub
        if future_github:
            gh_status, gh_payload, gh_err, gh_end = future_github.result()
            gh_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)
            if gh_payload: write_json(gh_path, gh_payload)
            insert_fetch_log(conn, run_id=run_id, package_name=package, source=GITHUB_SOURCE, endpoint=gh_end, fetched_at_utc=utc_now_iso(), http_status=gh_status, error=gh_err, raw_path=str(gh_path))
            if gh_payload: process_payload_with_agents(conn, run_id, package, GITHUB_SOURCE, gh_payload, run_github_agent)

        # Retrieve and process NVD
        nvd_status, nvd_payload, nvd_err, nvd_end = future_nvd.result()
        nvd_path = _raw_path_for(settings.data_dir, run_id, package, NVD_SOURCE)
        if nvd_payload: write_json(nvd_path, nvd_payload)
        insert_fetch_log(conn, run_id=run_id, package_name=package, source=NVD_SOURCE, endpoint=nvd_end, fetched_at_utc=utc_now_iso(), http_status=nvd_status, error=nvd_err, raw_path=str(nvd_path))
        if nvd_payload: process_payload_with_agents(conn, run_id, package, NVD_SOURCE, nvd_payload.get("vulnerabilities", []), run_nvd_agent)

if __name__ == "__main__":
    run_id = run_pipeline()
    print(f"\nDone. run_id = {run_id}")
    