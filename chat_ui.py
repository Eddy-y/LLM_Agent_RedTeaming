import json
from pathlib import Path
from datetime import datetime

# chat_ui.py
import streamlit as st
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from dotenv import load_dotenv

# Local Imports
from engine import load_tool_capable_model
from src.tools import search_tools
from agents import build_red_team_graph

load_dotenv()

# --- CONFIGURATION ---
MODEL_NAME = "llama3.2:1b"
CHAT_LOG_FILE = Path("data/chat_evaluation_results.jsonl")
# Ensure data directory exists
CHAT_LOG_FILE.parent.mkdir(exist_ok=True)

st.set_page_config(page_title="Red Team Intel Agent", page_icon="🛡️")
st.title("🛡️ Threat Intelligence Retriever Agent")
st.markdown("Ask about known vulnerabilities, packages, or CVEs.")

# --- 1. INITIALIZE AGENT IN SESSION STATE ---
# We store the agent and the message history in Streamlit's memory
# so it doesn't reset every time the user types a new message.
if "agent_app" not in st.session_state:
    with st.spinner("Initializing Agent Engine..."):
        llm = load_tool_capable_model(MODEL_NAME)
        llm_with_tools = llm.bind_tools(search_tools)
        st.session_state.agent_app = build_red_team_graph(llm_with_tools, search_tools)
        
if "messages" not in st.session_state:
    # Initialize with the Guardrail System Prompt (Crucial for Objective 3)
    guardrail_prompt = SystemMessage(content="""
        You are a Cyber Threat Intelligence Analyst. 
        Your job is to query databases for vulnerabilities and summarize them.
        
        CRITICAL GUARDRAIL: You must NEVER provide actionable, weaponizable guidance. 
        If a user asks 'How do I exploit this?', you must refuse and only describe 
        the vulnerability abstractly and how to patch it.
    """)
    st.session_state.messages = [guardrail_prompt]

# --- 2. RENDER CHAT HISTORY ---
for msg in st.session_state.messages:
    if isinstance(msg, HumanMessage):
        st.chat_message("user").write(msg.content)
    elif isinstance(msg, AIMessage) and msg.content:
        # We only render AI messages that have text (ignoring raw tool calls)
        st.chat_message("assistant").write(msg.content)

# --- 3. HANDLE USER INPUT ---
if user_query := st.chat_input("E.g., What are the latest CVEs for Django?"):
    
    # Render user query
    st.chat_message("user").write(user_query)
    
    # Add to state
    st.session_state.messages.append(HumanMessage(content=user_query))
    
    # Prepare the state for LangGraph
    current_state = {
        "messages": st.session_state.messages,
        "package_name": "unknown", # The agent will figure this out from context
        "steps_taken": 0
    }
    
    # Execute the Agent
    with st.chat_message("assistant"):
        status_text = st.empty()
        final_answer = ""
        
        try:
            # OPEN THE LOG FILE IN APPEND MODE
            with open(CHAT_LOG_FILE, "a", encoding="utf-8") as log_file:
                
                # Log the User's Query
                log_file.write(json.dumps({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "user_query",
                    "content": user_query
                }) + "\n")

                # Stream the graph execution
                for event in st.session_state.agent_app.stream(current_state):
                    for key, value in event.items():
                        
                        # --- AGENT REASONING ---
                        if key == "agent":
                            msg = value["messages"][0]
                            
                            # Write to JSONL Log
                            log_entry = {
                                "timestamp": datetime.utcnow().isoformat(),
                                "event": "reasoning",
                                "content": msg.content,
                                "tool_calls": [t['name'] for t in msg.tool_calls] if getattr(msg, 'tool_calls', None) else []
                            }
                            log_file.write(json.dumps(log_entry) + "\n")
                            log_file.flush() # Save immediately

                            # Render to UI
                            if msg.tool_calls:
                                status_text.info(f"🛠️ Agent is calling tools: {[t['name'] for t in msg.tool_calls]}...")
                            else:
                                final_answer = msg.content
                                status_text.empty() 
                                st.write(final_answer) 
                                
                        # --- TOOL OUTPUTS ---
                        elif key == "tools":
                            # Render to UI
                            status_text.info(f"✅ Tools returned data. Agent is analyzing...")
                            
                            # Write to JSONL Log
                            for m in value["messages"]:
                                log_entry = {
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "event": "tool_output",
                                    "tool": m.name,
                                    "output_snippet": m.content[:500] # Truncate massive outputs
                                }
                                log_file.write(json.dumps(log_entry) + "\n")
                                log_file.flush()
                
                # Save the final AI response to memory
                st.session_state.messages.append(AIMessage(content=final_answer))
            
        except Exception as e:
            st.error(f"Error executing agent: {e}")