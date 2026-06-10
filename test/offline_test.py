import json
from pathlib import Path
from src.agents import run_nvd_agent, run_github_agent, run_central_normalizer

# Define the base path using your latest data batch
base_path = Path("data/raw/2026_06_10t19_32_59_087559_00_00/flask")

def test_pipeline():
    # --- 1. Test NVD Prompt Extraction ---
    print("=== Testing NVD Agent ===")
    try:
        with open(base_path / "nvd.json", "r", encoding="utf-8") as f:
            nvd_raw = json.load(f)
            
        # Mimic ingest_to_sqs.py: extract the vulnerabilities list
        vulns = nvd_raw.get("vulnerabilities", [])
        if vulns:
            # Grab just the first vulnerability payload for a fast test
            sample_nvd_item = vulns[0] 
            
            print("1. Querying Specialist Agent...")
            nvd_specialist_out = run_nvd_agent([sample_nvd_item], "flask")
            print(f"Specialist Output: {json.dumps(nvd_specialist_out, indent=2)}\n")
            
            if nvd_specialist_out:
                print("2. Querying Central Normalizer...")
                nvd_normalized = run_central_normalizer(nvd_specialist_out, "nvd")
                print(f"Normalized Output: {json.dumps(nvd_normalized, indent=2)}\n")
        else:
            print("No vulnerabilities found in nvd.json.")
    except FileNotFoundError:
        print("nvd.json not found in the specified path.")

    # --- 2. Test GitHub Prompt Extraction ---
    print("=== Testing GitHub Agent ===")
    try:
        with open(base_path / "github_advisories.json", "r", encoding="utf-8") as f:
            gh_raw = json.load(f)
            
        sample_gh_item = None
        
        # Safely extract the first item whether the JSON is a list or a nested dictionary
        if isinstance(gh_raw, list) and len(gh_raw) > 0:
            sample_gh_item = gh_raw[0]
        elif isinstance(gh_raw, dict):
            # Look for the first dictionary key that contains a list
            for key, val in gh_raw.items():
                if isinstance(val, list) and len(val) > 0:
                    sample_gh_item = val[0]
                    break

        if sample_gh_item:
            print("1. Querying Specialist Agent...")
            gh_specialist_out = run_github_agent([sample_gh_item])
            print(f"Specialist Output: {json.dumps(gh_specialist_out, indent=2)}\n")
            
            if gh_specialist_out:
                print("2. Querying Central Normalizer...")
                gh_normalized = run_central_normalizer(gh_specialist_out, "github_advisories")
                print(f"Normalized Output: {json.dumps(gh_normalized, indent=2)}\n")
        else:
            print("Could not find a valid list of advisories in the GitHub JSON.")
            
    except FileNotFoundError:
        print("github_advisories.json not found in the specified path.")

if __name__ == "__main__":
    test_pipeline()