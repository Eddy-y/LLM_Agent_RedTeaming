import json
import pandas as pd
from pathlib import Path
from langchain_core.messages import HumanMessage

# --- Local Imports ---
from src.db import connect
from engine import load_tool_capable_model
from src.tools import search_tools       # Ensure this exists from Step 1
from agents import build_red_team_graph  # IMPORT THE NEW GRAPH BUILDER

# --- CONFIGURATION ---
DB_PATH = Path("data/pipeline.sqlite")
FULL_LOG_FILE = Path("data/evaluation_results.jsonl")  # Logs the "Reasoning" (Step 4)
SUMMARY_FILE = Path("data/agent_summary.csv")          # Final Report
MODEL_NAME = "llama3.2:1b"

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
            
            # 2. Run the Graph & Stream Steps (The "Evaluation" of Reasoning)
            try:
                for event in app.stream(initial_state): # Here goes in.
                    for key, value in event.items():
                        
                        # CASE A: Agent is Thinking
                        if key == "agent":
                            msg = value["messages"][0]
                            
                            # Log to Console
                            if msg.tool_calls:
                                print(f"  👉 [Decision]: Calling {len(msg.tool_calls)} tools...")
                                tool_calls_made.extend([t['name'] for t in msg.tool_calls])
                            else:
                                print(f"  📝 [Conclusion]: {msg.content[:60]}...")
                                final_response = msg.content

                            # Log to File (Step 4 Requirement)
                            log_entry = {
                                "package": pkg,
                                "event": "reasoning",
                                "content": msg.content,
                                "tool_calls": [t['name'] for t in msg.tool_calls]
                            }
                            log_file.write(json.dumps(log_entry) + "\n")

                        # CASE B: Tool is Executing
                        elif key == "tools":
                            print(f"  ✅ [Action]: Tool execution finished.")
                            # Log tool outputs
                            for m in value["messages"]:
                                log_entry = {
                                    "package": pkg,
                                    "event": "tool_output",
                                    "tool": m.name,
                                    "output_snippet": m.content[:200]
                                }
                                log_file.write(json.dumps(log_entry) + "\n")
                                
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
        llm_with_tools = llm.bind_tools(search_tools)
        
        # Build the Graph using our modular function
        agent_app = build_red_team_graph(llm_with_tools, search_tools)
        print("✅ Agent Graph compiled successfully.")
        
    except Exception as e:
        print(f"❌ Failed to load model/graph: {e}")
        return

    # 2. Fetch Targets
    if not DB_PATH.exists():
        print(f"Error: DB not found at {DB_PATH}")
        return

    conn = connect(DB_PATH)
    # Get distinct packages to test
    cursor = conn.execute("SELECT DISTINCT package_name FROM fetch_log")
    packages = [row['package_name'] for row in cursor.fetchall()]
    
    # 3. Run Evaluation (The Step 4 Function)
    summary_data = run_red_team_evaluation(agent_app, packages[:3]) # Limit to 3 for testing

    # 4. Export Final Report
    if summary_data:
        df = pd.DataFrame(summary_data)
        df.to_csv(SUMMARY_FILE, index=False)
        print(f"\n✅ Done! Summary saved to {SUMMARY_FILE}")
        print(f"✅ Reasoning logs at {FULL_LOG_FILE}")

if __name__ == "__main__":
    main()