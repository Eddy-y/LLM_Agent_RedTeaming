"""
config.py

Central place for configuration.
Uses environment variables so you do not hardcode secrets.

Environment variables
  GITHUB_TOKEN  optional but recommended for GitHub advisories rate limits
  NVD_API_KEY   optional but recommended for NVD rate limits

Notes
  This file should stay boring
  It only reads env vars and defines defaults
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


# --- YOUR AI & CTI CONSTANTS ---
OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2"
CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

def _env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("data")
    db_path: Path = Path("data") / "pipeline.sqlite"

    packages: tuple[str, ...] = ("django","flask", "requests")

    github_token: str | None = _env("GITHUB_TOKEN")
    nvd_api_key: str | None = _env("NVD_API_KEY")

    http_timeout_seconds: int = 30
    user_agent: str = "cs-poc-data-pipeline/1.0"


def get_settings() -> Settings:
    return Settings()
