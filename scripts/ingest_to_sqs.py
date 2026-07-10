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

from src.config import get_settings
from scripts.utils import ensure_dir, safe_slug, utc_now_iso, write_json

from src.sources.pypi import fetch_pypi_json, PYPI_SOURCE
from src.sources.github_advisories import fetch_github_advisories, GITHUB_SOURCE
from src.sources.nvd import fetch_nvd_cves, NVD_SOURCE

from scripts.fetchers import fetch_mitre_objects, fetch_capec_objects
from scripts.state import (
    load_universal_state,
    load_package_state,
    advance_mitre_offset,
    advance_capec_offset,
    advance_nvd_offset,
    advance_github_offset
)
from src.db import get_db_connection, release_db_connection

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
        print(f"    [WARN] DB connection unavailable, skipping deduplication check for {package_name}")
        return set()

    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT canonical_id FROM threat_intelligence_records WHERE package_name = %s AND source = %s",
                (package_name, source)
            )
            return {row[0] for row in cur.fetchall() if row[0]}
    except Exception as e:
        print(f"    [WARN] Error fetching existing IDs for {package_name}/{source}: {e}")
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
        # MITRE ATT&CK: Extract external_id from external_references (e.g., "T1055.011")
        # Agents normalize to this human-readable format, not the STIX ID
        refs = raw_item.get("external_references", [])
        for ref in refs:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]
        return None
    elif source == "capec":
        # CAPEC: Extract CAPEC-### ID from external_references
        # Agents normalize to this format (e.g., "CAPEC-1")
        refs = raw_item.get("external_references", [])
        for ref in refs:
            if ref.get("source_name") == "capec" and ref.get("external_id"):
                return ref["external_id"]
        return None
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
        print(f"    [DEDUP] Filtered {filtered_count}/{len(raw_items)} existing {source} items for {package}")

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
    state = load_universal_state()

    mitre_offset = state.get("mitre_offset", 0)
    mitre_data = fetch_mitre_objects(offset=mitre_offset, limit=5)
    if mitre_data and mitre_data.get("objects"):
        mitre_objects = mitre_data["objects"]
        new_mitre = filter_new_items(mitre_objects, "Universal", "attack")
        if new_mitre:
            push_to_sqs(run_id, "Universal", "attack", new_mitre)
            print(f"    [SQS] Queued {len(new_mitre)} new MITRE objects")
        else:
            print(f"    [INFO] All {len(mitre_objects)} MITRE objects already exist")

        # Always advance offset to move forward in history (even if all duplicates)
        advance_mitre_offset(len(mitre_objects))
        print(f"    [STATE] Advanced MITRE offset by {len(mitre_objects)} (new offset: {mitre_offset + len(mitre_objects)})")

    capec_offset = state.get("capec_offset", 0)
    capec_data = fetch_capec_objects(offset=capec_offset, limit=5)
    if capec_data and capec_data.get("objects"):
        capec_objects = capec_data["objects"]
        new_capec = filter_new_items(capec_objects, "Universal", "capec")
        if new_capec:
            push_to_sqs(run_id, "Universal", "capec", new_capec)
            print(f"    [SQS] Queued {len(new_capec)} new CAPEC objects")
        else:
            print(f"    [INFO] All {len(capec_objects)} CAPEC objects already exist")

        # Always advance offset to move forward in history (even if all duplicates)
        advance_capec_offset(len(capec_objects))
        print(f"    [STATE] Advanced CAPEC offset by {len(capec_objects)} (new offset: {capec_offset + len(capec_objects)})")

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
        
    # Fetch GitHub Advisories with pagination
    if settings.github_token:
        github_offset = load_package_state(package, 'github_advisories')
        print(f"    [GitHub] Fetching from page={github_offset}")

        gh_status, gh_payload, gh_err, gh_end = fetch_github_advisories(
            package,
            github_token=settings.github_token,
            timeout_seconds=settings.http_timeout_seconds,
            user_agent=settings.user_agent,
            start_page=github_offset,
            max_items=20
        )
        gh_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)

        if gh_payload:
            write_json(gh_path, gh_payload)
            nodes = gh_payload.get("nodes", [])

            # Deduplicate before queuing
            new_advisories = filter_new_items(nodes, package, GITHUB_SOURCE)

            if new_advisories:
                push_to_sqs(run_id, package, GITHUB_SOURCE, new_advisories)
                print(f"    [SQS] Queued {len(new_advisories)} new GitHub advisories")
            else:
                print(f"    [INFO] All {len(nodes)} GitHub advisories already exist for: {package}")

            # Advance state if we got results
            if len(nodes) > 0:
                advance_github_offset(package, 1)
                print(f"    [STATE] Advanced GitHub page offset by 1 for {package} (new page: {github_offset + 1})")

                pagination_meta = gh_payload.get("_pagination_meta", {})
                if pagination_meta.get("has_more_pages"):
                    print(f"    [INFO] GitHub has more pages available for {package}")
        else:
            print(f"    [WARN] GitHub Advisories fetch failed for {package}. Status: {gh_status} | Error: {gh_err}")

    # Fetch NVD CVEs with pagination
    nvd_offset = load_package_state(package, 'nvd')
    print(f"    [NVD] Fetching from startIndex={nvd_offset}")

    nvd_status, nvd_payload, nvd_err, nvd_end = fetch_nvd_cves(
        package,
        api_key=settings.nvd_api_key,
        timeout_seconds=settings.http_timeout_seconds,
        user_agent=settings.user_agent,
        start_index=nvd_offset,
        results_per_page=20
    )
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

                print(f"    [SQS] Queuing {len(new_vulns)} new NVD items for processing...")
                push_to_sqs(run_id, package, NVD_SOURCE, new_vulns)

                # Advance state after successful processing
                advance_nvd_offset(package, len(vulns))
                print(f"    [STATE] Advanced NVD offset by {len(vulns)} for {package} (new offset: {nvd_offset + len(vulns)})")
            else:
                print(f"    [INFO] All {len(vulns)} NVD records already exist for: {package}")
                # Still advance offset even if all duplicates (move forward in history)
                advance_nvd_offset(package, len(vulns))
                print(f"    [STATE] Advanced NVD offset by {len(vulns)} for {package} (all duplicates)")

            # Check if there are more pages
            pagination_meta = nvd_payload.get("_pagination_meta", {})
            if pagination_meta.get("has_more_pages"):
                print(f"    [INFO] NVD has more pages available for {package}")
        else:
            print(f"    [INFO] NVD returned 0 active CVE records for: {package}")
    else:
        print(f"    [WARN] NVD Fetch failed for {package}. Status: {nvd_status} | Error: {nvd_err}")

if __name__ == "__main__":
    run_id = run_pipeline()
    print(f"\nDone. run_id = {run_id}")