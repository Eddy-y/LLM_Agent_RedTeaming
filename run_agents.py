import json
import pandas as pd
from pathlib import Path
from langchain_core.messages import HumanMessage
from dotenv import load_dotenv 

load_dotenv()

# --- Local Imports ---
from src.db import connect
from engine import load_tool_capable_model
from src.tools import search_tools       
from agents import build_red_team_graph  

# --- CONFIGURATION ---
DB_PATH = Path("data/pipeline.sqlite")
FULL_LOG_FILE = Path("data/evaluation_results.jsonl")  # Logs the "Reasoning" (Step 4)
SUMMARY_FILE = Path("data/agent_summary.csv")          # Final Report
MODEL_NAME = "llama3.2:3b"


def run_red_team_evaluation(app, packages):
    """
    Step 4 Implementation: Iterates through packages and logs the agent's autonomy.
    """
    results_summary = []
    
    print(f"\n--- 🕵️ STARTING EVALUATION ON {len(packages)} PACKAGES ---")
    
    # Open the log file in append mode or write mode
    with open(FULL_LOG_FILE, "w", encoding="utf-8") as log_file:
        
        for pkg in packages:
            print(f"\n📦 Investigating: {pkg}")
            
            # 1. Define the Goal
            initial_state = {
                "messages": [HumanMessage(content=f"""
                    You are a Security Researcher. Investigate the python package '{pkg}'.
                    1. Check if it exists on PyPI.
                    2. Search for any known security advisories on GitHub or NVD.
                    3. Synthesize your findings into a brief security report.
                    Only call tools if you need information.
                """)],
                "package_name": pkg,
                "steps_taken": 0
            }

            final_response = "No response"
            tool_calls_made = []
            
            # 2. Run the Graph & Stream Steps
            try:
                for event in app.stream(initial_state): 
                    for key, value in event.items():
                        
                        # CASE A: Agent 1 (Retriever)
                        if key == "researcher":
                            msg = value["messages"][0]
                            if msg.tool_calls:
                                print(f"  🕵️ [Agent 1]: Fetching data with {len(msg.tool_calls)} tools...")
                                tool_calls_made.extend([t['name'] for t in msg.tool_calls])
                            
                            log_file.write(json.dumps({
                                "package": pkg,
                                "event": "agent_1_retriever",
                                "content": msg.content,
                                "tool_calls": [t['name'] for t in msg.tool_calls] if hasattr(msg, 'tool_calls') else []
                            }) + "\n")

                        # CASE B: Tools
                        elif key == "tools":
                            print(f"  ✅ [Action]: Tool execution finished.")
                            for m in value["messages"]:
                                log_file.write(json.dumps({
                                    "package": pkg,
                                    "event": "tool_output",
                                    "tool": m.name,
                                    "output_snippet": m.content[:200]
                                }) + "\n")
                                
                        # CASE C: Agent 2 (Analyzer)
                        elif key == "analyzer":
                            msg = value["messages"][0]
                            print(f"  📝 [Agent 2]: Report Generated.")
                            final_response = msg.content # This is the final report
                            
                            log_file.write(json.dumps({
                                "package": pkg,
                                "event": "agent_2_analyzer",
                                "content": msg.content
                            }) + "\n")
                                
            except Exception as e:
                print(f"  ❌ Error processing {pkg}: {e}")
                final_response = f"ERROR: {str(e)}"

            # 3. Save Summary
            results_summary.append({
                "package": pkg,
                "final_report": final_response,
                "tools_used": str(tool_calls_made),
            })
            log_file.flush() # Ensure data is safe

    return results_summary

def main():
    # 1. Initialize Brain
    try:
        llm = load_tool_capable_model(MODEL_NAME)
        
        # Build the Graph using the RAW LLM
        agent_app = build_red_team_graph(llm, search_tools)
        print("✅ Multi-Agent Graph compiled successfully.")
        
    except Exception as e:
        print(f"❌ Failed to load model/graph: {e}")
        return

    # 2. Fetch Targets from config.py
    # Ensure you import get_settings at the top of your file:
    # from src.config import get_settings
    from src.config import get_settings 
    
    settings = get_settings()
    packages = list(settings.packages)
    print(f"📦 Loaded packages from config: {packages}")
    
    if not packages:
        print("❌ No packages found in config.py.")
        return

    # 3. Run Evaluation
    summary_data = run_red_team_evaluation(agent_app, packages)

    # 4. Export Final Report
    if summary_data:
        df = pd.DataFrame(summary_data)
        df.to_csv(SUMMARY_FILE, index=False)
        print(f"\n✅ Done! Summary saved to {SUMMARY_FILE}")
        print(f"✅ Reasoning logs at {FULL_LOG_FILE}")

if __name__ == "__main__":
    main()