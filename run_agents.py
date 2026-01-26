import json
import sqlite3
import pandas as pd
from pathlib import Path
from langchain_ollama import OllamaLLM  # Or your preferred LLM class
from agents import get_agent_chains      # Importing your agent definition
from src.db import connect
from src.utils import read_json
from engine import load_optimized_pipeline
from langchain_huggingface import HuggingFacePipeline


# --- CONFIGURATION ---
DB_PATH = Path("data/pipeline.sqlite")
FULL_LOG_FILE = Path("data/evaluation_results.jsonl")  # The detailed line-by-line log
LLM_ONLY_FILE = Path("data/llm_responses.csv")         # New file for just responses
MODEL_NAME = "microsoft/Phi-3.5-mini-instruct"  # Example of a local GPTQ model

def get_full_raw_text(row):
    """
    The DB only has a summary. We need the full messy text from the raw file.
    """
    raw_path = Path(row["raw_path"])
    item_id = row["item_id"]
    source = row["source"]
    
    try:
        data = read_json(raw_path)
    except FileNotFoundError:
        return f"Error: Raw file not found at {raw_path}"

    # NAVIGATE THE MESSY RAW DATA
    # We must find the specific node that matches our item_id.
    # This logic mirrors the partner's extraction but grabs the FULL description.
    
    full_text = ""
    
    if source == "github_advisories":
        # Structure: {"nodes": [...]}
        nodes = data.get("nodes", [])
        for node in nodes:
            if node.get("ghsaId") == item_id:
                # We want the description, which partner's code ignored!
                full_text = f"Summary: {node.get('summary')}\nDescription: {node.get('description')}"
                break
                
    elif source == "nvd":
        # Structure: {"vulnerabilities": [{"cve": ...}]}
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            cve = v.get("cve", {})
            if cve.get("id") == item_id:
                # Join all English descriptions
                descs = [d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en']
                full_text = "\n".join(descs)
                break
                
    elif source == "pypi":
        # Structure: {"info": ...} - PyPI is one file per package
        info = data.get("info", {})
        if info.get("name") == item_id or item_id == row["package_name"]:
            full_text = f"Summary: {info.get('summary')}\nDescription: {info.get('description')}"

    return full_text if full_text else f"Error: Could not find item {item_id} in raw file."

def main():
    print(f"🚀 Starting Agent Evaluation System using {MODEL_NAME}...")
    
    # 1. INITIALIZE ENGINE (Hardware Detection & Model Loading)
    try:
        # Calls the function from engine.py
        hf_pipe = load_optimized_pipeline(MODEL_NAME)
        llm = HuggingFacePipeline(pipeline=hf_pipe)
    except Exception as e:
        print(f"❌ Critical Error: Failed to load model. {e}")
        return
    
    # Calls the function from agents.py
    chains = get_agent_chains(llm)
    collector_chain = chains['collector']
    normalizer_chain = chains['normalizer']
    
    # 2. Connect to DB
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}. Run pipeline.py first.")
        return

    conn = connect(DB_PATH)
    
    # 3. Fetch Candidates
    # We only care about Advisories and CVEs for this Red Teaming test
    cursor = conn.execute(
        "SELECT * FROM extracted_items WHERE item_type IN ('advisory', 'cve')"
    )
    rows = cursor.fetchall()
    
    rows = rows[:3]  # LIMIT for testing; remove or adjust as needed
    print(f"TEST MODE: Limiting to the first {len(rows)} items.")
    print(f"Found {len(rows)} items to process.")

    results_for_csv = []
    
    # 4. Run Loop
    with open(FULL_LOG_FILE, "w", encoding="utf-8") as f:
        for i, row in enumerate(rows):
            print(f"Processing {i+1}/{len(rows)}: {row['item_id']} ({row['source']})")
            
            # A. Get the messy raw input
            raw_input = get_full_raw_text(row)
            
            # B. Run Collector Agent (Filter Noise)
            try:
                collector_result = collector_chain.invoke({"raw_data": raw_input})
            except Exception as e:
                collector_result = f"AGENT ERROR: {str(e)}"

            # C. Run Normalizer Agent (Structure Data)
            try:
                normalizer_result = normalizer_chain.invoke({"collector_output": collector_result})
            except Exception as e:
                normalizer_result = f"AGENT ERROR: {str(e)}"
            
            # D. Save Result
            result_record = {
                "run_id": row["run_id"],
                "item_id": row["item_id"],
                "source": row["source"],
                "raw_input_snippet": raw_input[:200] + "...",
                "collector_output": collector_result,
                "normalizer_output": normalizer_result
            }
            
            f.write(json.dumps(result_record) + "\n")
            f.flush() # Ensure it writes to disk immediately

            # Add to list for CSV
            results_for_csv.append(result_record)

    # 5. EXPORT RESULTS (CSV)
    print(f"\n--- Exporting Results ---")
    if results_for_csv:
        df = pd.DataFrame(results_for_csv)
        
        # Optional: Select only specific columns for the clean CSV
        #df_clean = df[["item_id", "source", "collector_output", "normalizer_output"]]
        df_clean = df[["item_id", "source", "normalizer_output"]]
        
        df_clean.to_csv(LLM_ONLY_FILE, index=False)
        print(f"✅ Success! LLM responses written to: {LLM_ONLY_FILE}")
        print(f"✅ Full logs (including raw inputs) at: {FULL_LOG_FILE}")
    else:
        print("\n⚠️ Warning: No results were generated.")


if __name__ == "__main__":
    main()