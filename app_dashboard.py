import os
import json
import requests
import pandas as pd
from src.db import get_db_connection
import streamlit as st

# Setup page layout (Strictly flat and professional, no gradients)
st.set_page_config(page_title="CTI Analytics & Sandbox", layout="wide")
st.title("🛡️ Cyber Threat Intelligence Platform")

# Sidebar navigation - Updated to include your paper's experimental metrics dashboard
view = st.sidebar.radio(
    "Navigation Views", 
    ["Red-Team Sandbox Terminal", "Threat Matrix", "Audit logs", "Research Metrics"]
)

# Base FastAPI Endpoint URL
API_BASE_URL = "http://localhost:8000"


# --- VIEW 1: RED-TEAM SANDBOX TERMINAL ---
if view == "Red-Team Sandbox Terminal":
    st.subheader("🤖 Agent Sandbox Playground")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        target_package = st.text_input("Target Package Name (optional)", placeholder="e.g., django")
        adversarial_prompt = st.text_area("Prompt", placeholder="e.g., How could a supply chain attack target open-source dependencies?", height=150)
        deploy_btn = st.button("Deploy Analysis Agent", use_container_width=True)

    with col2:
        st.write("**Real-Time Agent Logs & Analysis Result**")
        if deploy_btn and (target_package or adversarial_prompt):
            with st.spinner("Invoking LangGraph Orchestrator..."):
                try:
                    # Pointing to your FastAPI streaming or execution wrapper
                    response = requests.post(
                        f"{API_BASE_URL}/generate_report_stream", 
                        json={"package_name": target_package, "prompt": adversarial_prompt},
                        stream=True
                    )
                    
                    log_placeholder = st.empty()
                    report_placeholder = st.empty()
                    
                    # Process lines coming back from the FastAPI Server-Sent Events (SSE) streaming handler
                    for line in response.iter_lines():
                        if line:
                            decoded_line = line.decode('utf-8').replace('data: ', '')
                            try:
                                data = json.loads(decoded_line)
                                if data.get('event') == 'complete':
                                    report_placeholder.markdown(f"### Final Generated Report\n\n{data['payload']['report']}")
                                    if data['payload'].get('guardrail_triggered'):
                                        st.error("⚠️ Active Interception Guardrail Node was Triggered!")
                                else:
                                    log_placeholder.text(f"[LANGGRAPH STATE]: Executing node -> {data.get('event')}")
                            except:
                                pass
                except Exception as e:
                    st.error(f"Backend API Connection Failed: {e}")
        else:
            st.info("Enter a package name, a prompt, or both — then click 'Deploy Agent'.")


# --- VIEW 2: THREAT MATRIX ---
elif view == "Threat Matrix":
    st.subheader("📦 Unified Normalized Threat Intelligence")
    
    try:
        res = requests.get(f"{API_BASE_URL}/api/v1/threats")
        if res.status_code == 200:
            threats = res.json()
            if threats:
                st.dataframe(threats, use_container_width=True)
            else:
                st.info("No threat vectors recorded in database yet.")
    except Exception as e:
        st.error(f"Could not load data from database API: {e}")


# --- VIEW 3: AUDIT LOGS ---
elif view == "Audit logs":
    st.subheader("🔍 Active Verifier & Hallucination Audits")
    
    try:
        res = requests.get(f"{API_BASE_URL}/api/v1/audits")
        if res.status_code == 200:
            audits = res.json()
            if audits:
                st.table(audits)
            else:
                st.info("No audit logs found.")
    except Exception as e:
        st.error(f"Could not load system logs: {e}")


# --- VIEW 4: RESEARCH METRICS VIEW ---
elif view == "Research Metrics":
    st.title("📊 Empirical Research Evaluation Metrics")
    st.subheader("Live Tracking from AWS RDS Cluster")
    
    try:
        conn = get_db_connection()
        if conn:
            # Pulling from evaluation_metrics table ordered by the database ID fallback
            df = pd.read_sql_query("SELECT * FROM evaluation_metrics ORDER BY id DESC;", conn)
            conn.close()
            
            if df.empty:
                st.warning("Database connected successfully, but the evaluation_metrics table is currently empty.")
            else:
                # Top performance summary cards for metric evaluation
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Evaluations Run", len(df))
                
                # Check for latency metric columns dynamically to prevent runtime exceptions
                if 'total_latency_sec' in df.columns and not df['total_latency_sec'].isna().all():
                    col2.metric("Avg Latency (Sec)", f"{df['total_latency_sec'].mean():.2f}s")
                else:
                    col2.metric("Avg Latency (Sec)", "0.00s")
                    
                if 'guardrail_triggered' in df.columns:
                    col3.metric("Guardrails Triggered", int(df['guardrail_triggered'].sum()))
                else:
                    col3.metric("Guardrails Triggered", "0")
                
                st.markdown("### Evaluation Records Data Grid")
                # Sleek spreadsheet display containing your model performance vectors
                st.dataframe(df, use_container_width=True)
                
                # Formats the underlying panda data frames as downloadable spreadsheets
                csv_data = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download Dataset as CSV",
                    data=csv_data,
                    file_name="aws_evaluation_metrics.csv",
                    mime="text/csv",
                    use_container_width=True
                )
    except Exception as e:
        st.error(f"Failed to fetch cloud records: {e}")