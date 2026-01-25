"""
pipeline.py

Orchestrates ingestion for each package and each data source.

Major responsibilities
  create run id
  initialize database
  fetch from sources
  write raw JSON payloads to disk
  write fetch_log entries
  extract intermediate items into extracted_items table

This file is your main interface for running the pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .config import get_settings
from .db import connect, init_db, insert_extracted_items, insert_fetch_log
from .utils import ensure_dir, safe_slug, utc_now_iso, write_json
from .sources.pypi import fetch_pypi_json, extract_pypi_item, PYPI_SOURCE
from .sources.github_advisories import (
    fetch_github_advisories,
    extract_github_items,
    GITHUB_SOURCE,
)
from .sources.nvd import fetch_nvd_cves, extract_nvd_items, NVD_SOURCE


def _raw_path_for(data_dir: Path, run_id: str, package: str, source: str) -> Path:
    """
    Computes a raw file path like:
      data/raw/{run_id}/{package}/{source}.json
    """
    pkg = safe_slug(package)
    src = safe_slug(source)
    return data_dir / "raw" / run_id / pkg / f"{src}.json"


def run_pipeline(packages: list[str] | None = None) -> str:
    """
    Runs the end to end ingestion and extraction.

    Returns run_id so you can reference this run later.
    """
    load_dotenv()
    settings = get_settings()

    run_id = safe_slug(utc_now_iso())
    data_dir = settings.data_dir
    ensure_dir(data_dir)

    conn = connect(settings.db_path)
    init_db(conn)

    if packages is None:
        packages = list(settings.packages)

    for package in packages:
        _run_for_package(conn, run_id, package, settings)

    conn.close()
    return run_id


def _run_for_package(conn, run_id: str, package: str, settings) -> None:
    """
    Runs ingestion for a single package across all sources.
    """
    print(f"\nRunning ingestion for package: {package}")

    extracted_rows: list[dict[str, Any]] = []

    pypi_raw_path = _raw_path_for(settings.data_dir, run_id, package, PYPI_SOURCE)
    status, payload, error, endpoint = fetch_pypi_json(
        package,
        timeout_seconds=settings.http_timeout_seconds,
        user_agent=settings.user_agent,
    )

    if payload is not None:
        write_json(pypi_raw_path, payload)

    insert_fetch_log(
        conn,
        run_id=run_id,
        package_name=package,
        source=PYPI_SOURCE,
        endpoint=endpoint,
        fetched_at_utc=utc_now_iso(),
        http_status=status,
        error=error,
        raw_path=str(pypi_raw_path),
    )

    if payload is not None:
        extracted_rows.append(
            extract_pypi_item(package, str(pypi_raw_path), payload, run_id)
        )

    if settings.github_token:
        gh_raw_path = _raw_path_for(settings.data_dir, run_id, package, GITHUB_SOURCE)
        status, payload, error, endpoint = fetch_github_advisories(
            package,
            github_token=settings.github_token,
            timeout_seconds=settings.http_timeout_seconds,
            user_agent=settings.user_agent,
        )

        if payload is not None:
            write_json(gh_raw_path, payload)

        insert_fetch_log(
            conn,
            run_id=run_id,
            package_name=package,
            source=GITHUB_SOURCE,
            endpoint=endpoint,
            fetched_at_utc=utc_now_iso(),
            http_status=status,
            error=error,
            raw_path=str(gh_raw_path),
        )

        if payload is not None:
            extracted_rows.extend(
                extract_github_items(package, str(gh_raw_path), payload, run_id)
            )
    else:
        print("Skipping GitHub advisories because GITHUB_TOKEN is not set.")

    nvd_raw_path = _raw_path_for(settings.data_dir, run_id, package, NVD_SOURCE)
    status, payload, error, endpoint = fetch_nvd_cves(
        package,
        api_key=settings.nvd_api_key,
        timeout_seconds=settings.http_timeout_seconds,
        user_agent=settings.user_agent,
    )

    if payload is not None:
        write_json(nvd_raw_path, payload)

    insert_fetch_log(
        conn,
        run_id=run_id,
        package_name=package,
        source=NVD_SOURCE,
        endpoint=endpoint,
        fetched_at_utc=utc_now_iso(),
        http_status=status,
        error=error,
        raw_path=str(nvd_raw_path),
    )

    if payload is not None:
        extracted_rows.extend(extract_nvd_items(package, str(nvd_raw_path), payload, run_id))

    if extracted_rows:
        insert_extracted_items(conn, extracted_rows)

    print(f"Extracted {len(extracted_rows)} items for {package}")

if __name__ == "__main__":
    run_id = run_pipeline()
    print(f"\nDone. run_id = {run_id}")
    print("Check data/raw for JSON files and data/pipeline.sqlite for DB output.")
