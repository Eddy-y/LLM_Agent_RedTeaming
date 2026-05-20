import os
import json
import requests
import streamlit as st

# Setup page layout (Strictly flat and professional, no gradients)
st.set_page_config(page_title="CTI Analytics & Sandbox", layout="wide")
st.title("🛡️ Cyber Threat Intelligence Platform")

# Sidebar navigation
view = st.sidebar.radio("Navigation Views", ["Red-Team Sandbox Terminal", "Threat Matrix", "Audit logs"])

# Base FastAPI Endpoint URL
API_BASE_URL = "http://localhost:8000"

# --- VIEW 1: RED-TEAM SANDBOX TERMINAL ---
if view == "Red-Team Sandbox Terminal":
    st.subheader("🤖 Agent Sandbox Playground")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        target_package = st.text_input("Target Package Name", placeholder="e.g., django")
        adversarial_prompt = st.text_area("Adversarial/Custom Prompt Override", placeholder="Analyze the package and suggest PoC...", height=150)
        deploy_btn = st.button("Deploy Analysis Agent", use_container_width=True)
        
    with col2:
        st.write("**Real-Time Agent Logs & Analysis Result**")
        if deploy_btn and target_package:
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
            st.info("Enter a package name and click 'Deploy Agent' to witness the LangGraph trace execution.")

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