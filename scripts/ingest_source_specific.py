"""
ingest_source_specific.py

Run ingestion for specific sources only with custom batch sizes.
Useful for balancing data collection or focusing on specific threat intelligence sources.

Usage:
    # Ingest only MITRE ATT&CK and CAPEC (50 items each)
    python scripts/ingest_source_specific.py --sources mitre capec --batch-size 50

    # Ingest only GitHub Advisories (100 items)
    python scripts/ingest_source_specific.py --sources github --batch-size 100

    # Ingest only NVD for specific packages
    python scripts/ingest_source_specific.py --sources nvd --packages flask django --batch-size 50

    # Ingest PyPI metadata only (always 1 item per package)
    python scripts/ingest_source_specific.py --sources pypi --packages numpy flask
"""

import sys
sys.path.insert(0, '.')

import argparse
import json
import os
from dotenv import load_dotenv
import boto3

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

# Import helper functions from main ingestion script
from scripts.ingest_to_sqs import (
    _raw_path_for,
    get_existing_ids,
    extract_id_from_raw,
    filter_new_items,
    push_to_sqs
)

load_dotenv()

def ingest_mitre(run_id: str, batch_size: int = 50):
    """Ingest MITRE ATT&CK techniques."""
    print(f"\n--- Ingesting MITRE ATT&CK (batch_size={batch_size}) ---")

    state = load_universal_state()
    mitre_offset = state.get("mitre_offset", 0)

    mitre_data = fetch_mitre_objects(offset=mitre_offset, limit=batch_size)
    if mitre_data and mitre_data.get("objects"):
        mitre_objects = mitre_data["objects"]

        # Filter out revoked/deprecated items
        active_mitre = [obj for obj in mitre_objects if not obj.get("revoked") and not obj.get("x_mitre_deprecated")]
        filtered_count = len(mitre_objects) - len(active_mitre)
        if filtered_count > 0:
            print(f"    [FILTER] Skipped {filtered_count} revoked/deprecated items")

        new_mitre = filter_new_items(active_mitre, "Universal", "attack")

        if new_mitre:
            push_to_sqs(run_id, "Universal", "attack", new_mitre)
            print(f"    [SUCCESS] Queued {len(new_mitre)} new MITRE objects")
        else:
            print(f"    [INFO] All {len(active_mitre)} active MITRE objects already exist")

        advance_mitre_offset(len(mitre_objects))
        print(f"    [STATE] Advanced MITRE offset to {mitre_offset + len(mitre_objects)}")
    else:
        print(f"    [WARN] No MITRE data fetched")

def ingest_capec(run_id: str, batch_size: int = 50):
    """Ingest CAPEC attack patterns."""
    print(f"\n--- Ingesting CAPEC (batch_size={batch_size}) ---")

    state = load_universal_state()
    capec_offset = state.get("capec_offset", 0)

    capec_data = fetch_capec_objects(offset=capec_offset, limit=batch_size)
    if capec_data and capec_data.get("objects"):
        capec_objects = capec_data["objects"]

        # Filter out deprecated items
        active_capec = [obj for obj in capec_objects if not obj.get("x_capec_status") == "Deprecated"]
        filtered_count = len(capec_objects) - len(active_capec)
        if filtered_count > 0:
            print(f"    [FILTER] Skipped {filtered_count} deprecated items")

        new_capec = filter_new_items(active_capec, "Universal", "capec")

        if new_capec:
            push_to_sqs(run_id, "Universal", "capec", new_capec)
            print(f"    [SUCCESS] Queued {len(new_capec)} new CAPEC objects")
        else:
            print(f"    [INFO] All {len(active_capec)} active CAPEC objects already exist")

        advance_capec_offset(len(capec_objects))
        print(f"    [STATE] Advanced CAPEC offset to {capec_offset + len(capec_objects)}")
    else:
        print(f"    [WARN] No CAPEC data fetched")

def ingest_pypi(run_id: str, packages: list[str], settings):
    """Ingest PyPI package metadata."""
    print(f"\n--- Ingesting PyPI for {len(packages)} packages ---")

    for package in packages:
        print(f"\n  Processing {package}...")
        p_status, p_payload, p_err, p_end = fetch_pypi_json(
            package,
            timeout_seconds=settings.http_timeout_seconds,
            user_agent=settings.user_agent
        )

        if p_payload:
            p_path = _raw_path_for(settings.data_dir, run_id, package, PYPI_SOURCE)
            write_json(p_path, p_payload)

            # Clean massive release history to avoid SQS 256KB limit
            cleaned_pypi_payload = {
                "info": p_payload.get("info", {}),
                "last_serial": p_payload.get("last_serial", 0)
            }

            push_to_sqs(run_id, package, PYPI_SOURCE, [cleaned_pypi_payload])
            print(f"    [SUCCESS] Queued PyPI metadata for {package}")
        else:
            print(f"    [WARN] PyPI fetch failed for {package}. Status: {p_status}")

def ingest_github(run_id: str, packages: list[str], settings, batch_size: int = 20):
    """Ingest GitHub Security Advisories."""
    print(f"\n--- Ingesting GitHub Advisories for {len(packages)} packages (batch_size={batch_size}) ---")

    if not settings.github_token:
        print("    [ERROR] GITHUB_TOKEN not configured. Skipping GitHub ingestion.")
        return

    for package in packages:
        print(f"\n  Processing {package}...")
        github_offset = load_package_state(package, 'github_advisories')

        gh_status, gh_payload, gh_err, gh_end = fetch_github_advisories(
            package,
            github_token=settings.github_token,
            timeout_seconds=settings.http_timeout_seconds,
            user_agent=settings.user_agent,
            start_page=github_offset,
            max_items=batch_size
        )

        if gh_payload:
            gh_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)
            write_json(gh_path, gh_payload)

            nodes = gh_payload.get("nodes", [])
            new_advisories = filter_new_items(nodes, package, GITHUB_SOURCE)

            if new_advisories:
                push_to_sqs(run_id, package, GITHUB_SOURCE, new_advisories)
                print(f"    [SUCCESS] Queued {len(new_advisories)} new GitHub advisories")
            else:
                print(f"    [INFO] All {len(nodes)} GitHub advisories already exist")

            if len(nodes) > 0:
                advance_github_offset(package, 1)
                print(f"    [STATE] Advanced GitHub page offset to {github_offset + 1}")
        else:
            print(f"    [WARN] GitHub fetch failed for {package}. Status: {gh_status}")

def ingest_nvd(run_id: str, packages: list[str], settings, batch_size: int = 20):
    """Ingest NVD CVE records."""
    print(f"\n--- Ingesting NVD CVEs for {len(packages)} packages (batch_size={batch_size}) ---")

    for package in packages:
        print(f"\n  Processing {package}...")
        nvd_offset = load_package_state(package, 'nvd')

        nvd_status, nvd_payload, nvd_err, nvd_end = fetch_nvd_cves(
            package,
            api_key=settings.nvd_api_key,
            timeout_seconds=settings.http_timeout_seconds,
            user_agent=settings.user_agent,
            start_index=nvd_offset,
            results_per_page=batch_size
        )

        if nvd_payload:
            nvd_path = _raw_path_for(settings.data_dir, run_id, package, NVD_SOURCE)
            write_json(nvd_path, nvd_payload)

            vulns = nvd_payload.get("vulnerabilities", [])
            if vulns:
                new_vulns = filter_new_items(vulns, package, NVD_SOURCE)

                if new_vulns:
                    # Add verified source URLs
                    for item in new_vulns:
                        cve_id = item.get("cve", {}).get("id", "")
                        item["verified_source_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://nvd.nist.gov"

                    push_to_sqs(run_id, package, NVD_SOURCE, new_vulns)
                    print(f"    [SUCCESS] Queued {len(new_vulns)} new NVD CVEs")
                else:
                    print(f"    [INFO] All {len(vulns)} NVD records already exist")

                advance_nvd_offset(package, len(vulns))
                print(f"    [STATE] Advanced NVD offset to {nvd_offset + len(vulns)}")
            else:
                print(f"    [INFO] NVD returned 0 CVE records")
        else:
            print(f"    [WARN] NVD fetch failed for {package}. Status: {nvd_status}")

def main():
    parser = argparse.ArgumentParser(
        description="Ingest from specific threat intelligence sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ingest 100 MITRE ATT&CK techniques
  python scripts/ingest_source_specific.py --sources mitre --batch-size 100

  # Ingest 50 CAPEC patterns
  python scripts/ingest_source_specific.py --sources capec --batch-size 50

  # Ingest both MITRE and CAPEC (50 each)
  python scripts/ingest_source_specific.py --sources mitre capec --batch-size 50

  # Ingest GitHub Advisories for specific packages
  python scripts/ingest_source_specific.py --sources github --packages flask django --batch-size 30

  # Ingest NVD CVEs for all configured packages
  python scripts/ingest_source_specific.py --sources nvd --batch-size 50

  # Ingest from all sources with custom batch size
  python scripts/ingest_source_specific.py --sources mitre capec github nvd pypi --batch-size 50
        """
    )

    parser.add_argument(
        '--sources',
        nargs='+',
        required=True,
        choices=['mitre', 'capec', 'github', 'nvd', 'pypi'],
        help='Sources to ingest from'
    )

    parser.add_argument(
        '--packages',
        nargs='+',
        help='Specific packages to ingest (for github/nvd/pypi). Uses config.py packages if not specified.'
    )

    parser.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Number of items to fetch per source (default: 50). Note: PyPI always fetches 1 item per package.'
    )

    args = parser.parse_args()

    # Load settings
    settings = get_settings()

    # Determine packages
    if args.packages:
        packages = args.packages
    else:
        packages = list(settings.packages)

    # Generate run ID
    run_id = safe_slug(utc_now_iso())
    ensure_dir(settings.data_dir)

    print("\n" + "=" * 70)
    print("SOURCE-SPECIFIC INGESTION")
    print("=" * 70)
    print(f"\nRun ID: {run_id}")
    print(f"Sources: {', '.join(args.sources)}")
    print(f"Packages: {', '.join(packages)}")
    print(f"Batch size: {args.batch_size}")
    print("\n" + "=" * 70)

    # Run ingestion for each selected source
    if 'mitre' in args.sources:
        ingest_mitre(run_id, args.batch_size)

    if 'capec' in args.sources:
        ingest_capec(run_id, args.batch_size)

    if 'pypi' in args.sources:
        ingest_pypi(run_id, packages, settings)

    if 'github' in args.sources:
        ingest_github(run_id, packages, settings, args.batch_size)

    if 'nvd' in args.sources:
        ingest_nvd(run_id, packages, settings, args.batch_size)

    print("\n" + "=" * 70)
    print("INGESTION COMPLETE")
    print("=" * 70)
    print(f"\nRun ID: {run_id}")
    print("\n[NEXT STEP] Monitor Lambda processing:")
    print("  - Check CloudWatch logs for Lambda worker")
    print("  - Run: python scripts/batch_ingestion.py --runs 1")
    print("    (to see current record counts)")
    print("\n")

if __name__ == "__main__":
    main()
