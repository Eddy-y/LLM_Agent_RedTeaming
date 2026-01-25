"""
utils.py

Small helper functions for:
  creating folders
  writing JSON to disk
  generating safe file names
  timestamps
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    """Returns current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(path: Path) -> None:
    """Creates a directory if it does not exist."""
    path.mkdir(parents=True, exist_ok=True)


def safe_slug(value: str) -> str:
    """
    Converts a string into a safe file or folder name.
    Example: "PyYAML 6.0" -> "pyyaml_6_0"
    """
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_")


def write_json(path: Path, payload: Any) -> None:
    """
    Writes JSON in a stable, readable format.
    Using ensure_ascii False so it does not mangle characters.
    """
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, sort_keys=True)


def read_json(path: Path) -> Any:
    """Reads JSON from disk."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
