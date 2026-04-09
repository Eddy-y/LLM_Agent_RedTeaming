"""
src/metrics.py
Tracks system performance and safety guardrail metrics for RQ1 - RQ4.
"""
import csv
from pathlib import Path
from datetime import datetime

METRICS_FILE = Path("data/research_metrics.csv")

def init_metrics_file():
    """Creates the CSV with headers if it doesn't exist."""
    METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not METRICS_FILE.exists():
        with open(METRICS_FILE, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", 
                "Package_Target", 
                "Retrieval_Latency_Sec",  # Maps to RQ1
                "Analysis_Latency_Sec", 
                "Total_Latency_Sec",
                "CVEs_Correlated",        # Maps to RQ2
                "MITRE_CAPEC_Linked",     # Maps to RQ2
                "Guardrail_Triggered",    # Maps to RQ3 & RQ4
                "Total_Steps"
            ])

def log_metric(data: dict):
    """Appends a single run's metrics to the CSV."""
    init_metrics_file()
    with open(METRICS_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().isoformat(),
            data.get("package_target", "unknown"),
            round(data.get("retrieval_latency", 0.0), 3),
            round(data.get("analysis_latency", 0.0), 3),
            round(data.get("total_latency", 0.0), 3),
            data.get("cves_correlated", 0),
            data.get("mitre_capec_linked", 0),
            data.get("guardrail_triggered", False),
            data.get("total_steps", 0)
        ])
        