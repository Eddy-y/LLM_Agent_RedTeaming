import streamlit as st
import pandas as pd
from pathlib import Path

# --- Local Imports ---
from run_agents import run_red_team_evaluation, SUMMARY_FILE, FULL_LOG_FILE, MODEL_NAME
from engine import load_tool_capable_model
from agents import build_red_team_graph
from src.tools import search_tools

# 1. Page Configuration
st.set_page_config(page_title="Agentic Red Teaming", page_icon="🛡️", layout="centered")
st.title("🛡️ Agentic Threat Intelligence")
st.write("Enter a Python package to autonomously gather and synthesize security advisories.")

# 2. Cache the Agent Initialization
# This ensures the model and graph are only loaded once per session, saving time.
@st.cache_resource(show_spinner="Initializing Agent Brain (Loading LLM)...")
def get_agent_app():
    llm = load_tool_capable_model(MODEL_NAME)
    agent_app = build_red_team_graph(llm, search_tools)
    return agent_app

try:
    agent_app = get_agent_app()
except Exception as e:
    st.error(f"Failed to load model/graph: {e}")
    st.stop()

# 3. User Interface
package_input = st.text_input("Package Name:", placeholder="e.g., flask, django, requests")

if st.button("Run Red Team Evaluation"):
    if not package_input.strip():
        st.warning("Please enter a package name to investigate.")
    else:
        package_name = package_input.strip()
        packages = [package_name]
        
        with st.spinner(f"🕵️ Agent is investigating '{package_name}'... (Check terminal for live thoughts)"):
            
            # Call the evaluation function
            summary_data = run_red_team_evaluation(agent_app, packages)
            
            if summary_data:
                result = summary_data[0]
                
                # --- Display the Results ---
                st.subheader(f"📝 Security Report: `{package_name}`")
                st.markdown(result.get("final_report", "No report generated."))
                
                with st.expander("🛠️ View Tools Used by Agent 1"):
                    st.write(result.get("tools_used", "None"))
                
                # --- Mimic main() Logging Behavior ---
                df = pd.DataFrame(summary_data)
                
                # Append to CSV if it exists, otherwise create it
                if Path(SUMMARY_FILE).exists():
                    df.to_csv(SUMMARY_FILE, mode='a', header=False, index=False)
                else:
                    df.to_csv(SUMMARY_FILE, index=False)
                
                # Display the terminal success messages in the UI
                st.success(f"✅ Done! Summary saved to `{SUMMARY_FILE}`")
                st.info(f"✅ Reasoning logs at `{FULL_LOG_FILE}`")
                
            else:
                st.error("Evaluation failed to return data.")

# Mertrics

st.divider()
st.subheader("📊 Live Research Metrics (RQ1 - RQ4)")

try:
    # Read the metrics CSV directly into the UI
    metrics_df = pd.read_csv("data/research_metrics.csv")
    
    # Display it as an interactive table
    st.dataframe(metrics_df, use_container_width=True)
    
    # Optional: Display a quick metric summary
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packages Scanned", len(metrics_df))
    col2.metric("Avg Total Latency", f"{metrics_df['Total_Latency_Sec'].mean():.2f}s")
    col3.metric("Guardrails Triggered", metrics_df['Guardrail_Triggered'].sum())
    
except FileNotFoundError:
    st.info("No metrics gathered yet. Run an evaluation to generate the data.")