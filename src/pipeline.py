"""
pipeline.py

Orchestrates ingestion for each package and each data source.
Extracts items using Explicit LLM Specialist Agents and Normalizer into unified DB.
"""

from __future__ import annotations

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

def _raw_path_for(data_dir: Path, run_id: str, package: str, source: str) -> Path:
    pkg = safe_slug(package)
    src = safe_slug(source)
    return data_dir / "raw" / run_id / pkg / f"{src}.json"


def run_pipeline(packages: list[str] | None = None) -> str:
    load_dotenv()
    settings = get_settings()

    run_id = safe_slug(utc_now_iso())
    data_dir = settings.data_dir
    ensure_dir(data_dir)

    conn = connect(settings.db_path)
    init_db(conn)

    # 1. Fetch Universal Attack Patterns (Runs once per pipeline execution)
    _run_universal_corpora(conn, run_id)

    # 2. Fetch Package-Specific Vulnerabilities (Loops per package)
    if packages is None:
        packages = list(settings.packages)

    for package in packages:
        _run_for_package(conn, run_id, package, settings)

    conn.close()
    return run_id


def process_payload_with_agents(conn, run_id, package, source_name, raw_items, agent_function):
    """
    Helper function to pass raw data through a specific Specialist -> Normalizer -> DB.
    """
    if not raw_items:
        return

    # 1. Pass data to the specific explicit Agent
    specialist_output = agent_function(raw_items)
    
    # 2. Pass intermediate data to the Central Normalizer Agent
    if specialist_output:
        normalized_data = run_central_normalizer(specialist_output)
        
        # 3. Save to the unified database table
        if normalized_data:
            insert_normalized_batch(conn, run_id, package, normalized_data)
            print(f"    [DB] Saved {len(normalized_data)} normalized records for {source_name}.")


# ==========================================
# UNIVERSAL CORPORA LOGIC (MITRE & CAPEC)
# ==========================================
def _run_universal_corpora(conn, run_id):
    """Fetches universal threat data (MITRE/CAPEC) in batches."""
    print("\n--- Processing Universal Corpora (MITRE & CAPEC) ---")
    state = load_state()
    
    # MITRE ATT&CK
    mitre_offset = state.get("mitre_offset", 0)
    mitre_data = fetch_mitre_objects(offset=mitre_offset, limit=5)
    if mitre_data and mitre_data.get("objects"):
        process_payload_with_agents(conn, run_id, "Universal", "attack", mitre_data["objects"], run_mitre_agent)
        advance_mitre_offset(5)
        
    # CAPEC
    capec_offset = state.get("capec_offset", 0)
    capec_data = fetch_capec_objects(offset=capec_offset, limit=5)
    if capec_data and capec_data.get("objects"):
        process_payload_with_agents(conn, run_id, "Universal", "capec", capec_data["objects"], run_capec_agent)
        advance_capec_offset(5)


# ==========================================
# PACKAGE-SPECIFIC LOGIC (PYPI, GITHUB, NVD)
# ==========================================
def _run_for_package(conn, run_id: str, package: str, settings) -> None:
    print(f"\nRunning ingestion for package: {package}")

    # --- 1. PYPI PIPELINE ---
    pypi_raw_path = _raw_path_for(settings.data_dir, run_id, package, PYPI_SOURCE)
    status, payload, error, endpoint = fetch_pypi_json(
        package, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent,
    )

    if payload is not None:
        write_json(pypi_raw_path, payload)

    insert_fetch_log(
        conn, run_id=run_id, package_name=package, source=PYPI_SOURCE,
        endpoint=endpoint, fetched_at_utc=utc_now_iso(), http_status=status,
        error=error, raw_path=str(pypi_raw_path),
    )

    if payload is not None:
        process_payload_with_agents(conn, run_id, package, PYPI_SOURCE, [payload], run_pypi_agent)

    # --- 2. GITHUB ADVISORIES PIPELINE ---
    if settings.github_token:
        gh_raw_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)
        status, payload, error, endpoint = fetch_github_advisories(
            package, github_token=settings.github_token, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent,
        )

        if payload is not None:
            write_json(gh_raw_path, payload)

        insert_fetch_log(
            conn, run_id=run_id, package_name=package, source=GITHUB_SOURCE,
            endpoint=endpoint, fetched_at_utc=utc_now_iso(), http_status=status,
            error=error, raw_path=str(gh_raw_path),
        )

        if payload is not None:
            process_payload_with_agents(conn, run_id, package, GITHUB_SOURCE, payload, run_github_agent)

    # --- 3. NVD PIPELINE ---
    nvd_raw_path = _raw_path_for(settings.data_dir, run_id, package, NVD_SOURCE)
    status, payload, error, endpoint = fetch_nvd_cves(
        package, api_key=settings.nvd_api_key, timeout_seconds=settings.http_timeout_seconds, user_agent=settings.user_agent,
    )

    if payload is not None:
        write_json(nvd_raw_path, payload)

    insert_fetch_log(
        conn, run_id=run_id, package_name=package, source=NVD_SOURCE,
        endpoint=endpoint, fetched_at_utc=utc_now_iso(), http_status=status,
        error=error, raw_path=str(nvd_raw_path),
    )

    if payload is not None:
        cves = payload.get("vulnerabilities", [])
        process_payload_with_agents(conn, run_id, package, NVD_SOURCE, cves, run_nvd_agent)


if __name__ == "__main__":
    run_id = run_pipeline()
    print(f"\nDone. run_id = {run_id}")
    