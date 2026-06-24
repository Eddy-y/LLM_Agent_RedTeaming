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
from .db import get_db_connection, release_db_connection

import dotenv
dotenv.load_dotenv()
# Initialize SQS client
sqs_client = boto3.client('sqs', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
sqs_queue_url = os.environ.get('SQS_QUEUE_URL')

def _raw_path_for(data_dir: Path, run_id: str, package: str, source: str) -> Path:
    pkg = safe_slug(package)
    src = safe_slug(source)
    return data_dir / "raw" / run_id / pkg / f"{src}.json"

def get_existing_ids(package_name: str, source: str) -> set[str]:
    """
    Query the database for existing canonical_ids for a given package and source.
    Returns a set of IDs to enable fast deduplication checks.
    """
    conn = get_db_connection()
    if not conn:
        print(f"    ⚠️ DB connection unavailable, skipping deduplication check for {package_name}")
        return set()

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT canonical_id FROM normalized_items WHERE package_name = %s AND source = %s",
                (package_name, source)
            )
            return {row[0] for row in cur.fetchall() if row[0]}
    except Exception as e:
        print(f"    ⚠️ Error fetching existing IDs for {package_name}/{source}: {e}")
        return set()
    finally:
        release_db_connection(conn)

def extract_id_from_raw(raw_item: dict, source: str) -> str | None:
    """
    Extract the canonical ID from raw data before LLM processing.
    This enables pre-LLM deduplication to save Bedrock compute.
    """
    if source == NVD_SOURCE:
        # NVD structure: {"cve": {"id": "CVE-2021-1234", ...}}
        return raw_item.get("cve", {}).get("id")
    elif source == GITHUB_SOURCE:
        # GitHub structure: {"ghsaId": "GHSA-xxxx-xxxx-xxxx", ...}
        return raw_item.get("ghsaId")
    elif source == PYPI_SOURCE:
        # PyPI doesn't have structured IDs in the raw payload, defer to LLM
        return None
    elif source == "attack":
        # MITRE ATT&CK structure: {"id": "attack-pattern--...", ...}
        return raw_item.get("id")
    elif source == "capec":
        # CAPEC structure: {"id": "attack-pattern--...", ...} or similar
        return raw_item.get("id")
    return None

def filter_new_items(raw_items: list[dict], package: str, source: str) -> list[dict]:
    """
    Filter out items that already exist in the database by canonical_id.
    This prevents redundant LLM processing and database overwrites.
    """
    if not raw_items:
        return []

    existing_ids = get_existing_ids(package, source)
    if not existing_ids:
        # No existing records, process all items
        return raw_items

    new_items = []
    for item in raw_items:
        item_id = extract_id_from_raw(item, source)
        if item_id is None:
            # Can't extract ID, let it through (e.g., PyPI case)
            new_items.append(item)
        elif item_id not in existing_ids:
            new_items.append(item)

    filtered_count = len(raw_items) - len(new_items)
    if filtered_count > 0:
        print(f"    ✅ Deduplicated {filtered_count}/{len(raw_items)} existing {source} items for {package}")

    return new_items

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
            QueueUrl=sqs_queue_url,
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
        new_mitre = filter_new_items(mitre_data["objects"], "Universal", "attack")
        if new_mitre:
            push_to_sqs(run_id, "Universal", "attack", new_mitre)
            advance_mitre_offset(5)
        else:
            print(f"    ℹ️ All {len(mitre_data['objects'])} MITRE objects already exist")

    capec_offset = state.get("capec_offset", 0)
    capec_data = fetch_capec_objects(offset=capec_offset, limit=5)
    if capec_data and capec_data.get("objects"):
        new_capec = filter_new_items(capec_data["objects"], "Universal", "capec")
        if new_capec:
            push_to_sqs(run_id, "Universal", "capec", new_capec)
            advance_capec_offset(5)
        else:
            print(f"    ℹ️ All {len(capec_data['objects'])} CAPEC objects already exist")

def _run_for_package(run_id: str, package: str, settings) -> None:
    print(f"\nRunning ingestion for package: {package}")

    # Fetch PyPI
    p_status, p_payload, p_err, p_end = fetch_pypi_json(package, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent)
    p_path = _raw_path_for(settings.data_dir, run_id, package, PYPI_SOURCE)
    if p_payload: 
        write_json(p_path, p_payload)
        
        # 🛡️ Architectural Fix: Clean the massive release history block to avoid SQS 413 Errors
        cleaned_pypi_payload = {
            "info": p_payload.get("info", {}),
            "last_serial": p_payload.get("last_serial", 0)
        }
        
        # Push only the trimmed, high-value metadata string to the SQS queue
        push_to_sqs(run_id, package, PYPI_SOURCE, [cleaned_pypi_payload])
        
    # Fetch GitHub Advisories
    if settings.github_token:
        gh_status, gh_payload, gh_err, gh_end = fetch_github_advisories(package, github_token=settings.github_token, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent)
        gh_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)
        if gh_payload:
            write_json(gh_path, gh_payload)
            # Deduplicate before queuing
            new_advisories = filter_new_items(gh_payload, package, GITHUB_SOURCE)
            push_to_sqs(run_id, package, GITHUB_SOURCE, new_advisories)

    # Fetch NVD CVEs
    nvd_status, nvd_payload, nvd_err, nvd_end = fetch_nvd_cves(package, api_key=settings.nvd_api_key, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent)
    nvd_path = _raw_path_for(settings.data_dir, run_id, package, NVD_SOURCE)

    if nvd_payload:
        write_json(nvd_path, nvd_payload)
        vulns = nvd_payload.get("vulnerabilities", [])

        if vulns:
            # Deduplicate before processing
            new_vulns = filter_new_items(vulns, package, NVD_SOURCE)

            if new_vulns:
                # Append verified links directly into the data payload before queuing
                for item in new_vulns:
                    cve_id = item.get("cve", {}).get("id", "")
                    item["verified_source_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://nvd.nist.gov"

                print(f"    [SQS] Queuing {len(new_vulns)} new items for nvd processing...")
                push_to_sqs(run_id, package, NVD_SOURCE, new_vulns)
            else:
                print(f"    ℹ️ All {len(vulns)} NVD records already exist for: {package}")
        else:
            print(f"    ℹ️ NVD returned 0 active CVE records for: {package}")
    else:
        print(f"    ⚠️ NVD Fetch failed for {package}. Status: {nvd_status} | Error: {nvd_err}")

if __name__ == "__main__":
    run_id = run_pipeline()
    print(f"\nDone. run_id = {run_id}")