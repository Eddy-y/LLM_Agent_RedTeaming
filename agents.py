import time
import json
import re
from typing import TypedDict, Annotated, Sequence
import operator
import threading
from src.verifier import run_verification_and_log

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, ToolMessage, AIMessage
from langgraph.graph import StateGraph, END
    

# ==========================================
# STATE MANAGEMENT
# ==========================================
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    package_name: str
    steps_taken: int
    # --- Metrics Tracking Fields ---
    start_time: float
    retrieval_time: float
    analysis_time: float
    guardrail_triggered: bool

MAX_STEPS = 6

def fetch_local_cti_data(keywords: list):
    """
    Heuristic Search: Looks for patterns/keywords in the PostgreSQL database 
    rather than exact package matches.
    """
    import psycopg2.extras
    from src.db import get_db_connection
    
    try:
        # 1. Connect to Amazon RDS
        conn = get_db_connection()
        if not conn:
            return "Error: Could not connect to the cloud database."
        
        # Use RealDictCursor so PostgreSQL rows behave exactly like Python dictionaries
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # 2. Build a dynamic SQL query using ILIKE for case-insensitive matching
        # and %s instead of ? for PostgreSQL parameter binding
        query_conditions = " OR ".join(["summary ILIKE %s OR title ILIKE %s" for _ in keywords])
        
        params = []
        for kw in keywords:
            params.extend([f"%{kw}%", f"%{kw}%"]) 
            
        sql = f"SELECT * FROM normalized_items WHERE {query_conditions} LIMIT 10"
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        
        # 3. Always close the connection to avoid maxing out the RDS pool!
        conn.close()
        
        if not rows:
            return f"No records found matching heuristic keywords: {keywords}"
            
        formatted_report = f"Heuristic Database Matches for {keywords}:\n\n"
        for row in rows:
            # Because we used RealDictCursor, 'row' is already a dictionary
            formatted_report += f"- ID: {row.get('canonical_id')} (Package: {row.get('package_name')}, Severity: {row.get('severity')})\n"
            formatted_report += f"  Summary: {row.get('summary')}\n\n"

        return formatted_report
        
    except Exception as e:
        return f"Database error: {e}"
    
# ==========================================
# LANGGRAPH PIPELINE (DETERMINISTIC RETRIEVAL)
# ==========================================
def build_red_team_graph(llm, tools=None):
    """
    Constructs a linear StateGraph.
    Tools are no longer passed to the LLM because retrieval is deterministic.
    """
    
    def researcher_node(state):
        import time
        t0 = time.time()
        
        # 1. Get the actual prompt you typed into Streamlit
        user_query = state.get('package_name', '') 
        
        # 2. Dynamically generate heuristic keywords by removing stop words
        stop_words = {"tell", "me", "about", "are", "there", "any", "the", "a", "an", "of", "and", "or", "in", "to", "for"}
        raw_words = user_query.lower().replace("?", "").replace(".", "").split()
        
        # Keep only meaningful keywords longer than 2 letters
        heuristic_keywords = [word for word in raw_words if word not in stop_words and len(word) > 2]
        
        # Fallback just in case
        if not heuristic_keywords:
            heuristic_keywords = ["vulnerability"]
            
        # 3. Execute heuristic search dynamically
        raw_cti_data = fetch_local_cti_data(heuristic_keywords)
        
        print("\n" + "="*60)
        print(f" 🔍 [RETRIEVER] DYNAMIC HEURISTIC SEARCH EXECUTED")
        print(f"    User Query: '{user_query}'")
        print(f"    Keywords Extracted: {heuristic_keywords}")
        print("-" * 60)
        print(" 📄 [PAYLOAD SENT TO LLM]:")
        print(f"{raw_cti_data}")
        print("="*60 + "\n")
        
        step_time = time.time() - t0

        from langchain_core.messages import ToolMessage
        simulated_tool_response = ToolMessage(
            content=str(raw_cti_data),
            name="search_local_cti",
            tool_call_id="deterministic_fetch_1"
        )
        
        return {
            "messages": [simulated_tool_response],
            "retrieval_time": step_time
        }

    def analyzer_node(state):
        t0 = time.time()
        messages = state['messages']
        
        analyzer_prompt = SystemMessage(content="""
            You are a Cyber Threat Intelligence Analyst for the PYTHON ecosystem.
            
            YOUR GOAL: Evaluate the database records against the user's query and generate a JSON response.
            
            CRITICAL RULES:
            1. RELEVANCE CHECK: You must first determine if the database records actually match the user's specific topic. (e.g., "Active Directory" is a Microsoft Windows concept, which is NOT the same as "Directory Traversal" in Python web apps).
            2. NO RECOMMENDATIONS: Do not include mitigations or recommendations.
            3. STRICT JSON: You MUST return ONLY a valid JSON object. Do not include markdown formatting like ```json.
            
            OUTPUT FORMAT:
            {
                "is_relevant": true or false,
                "reasoning": "1 sentence explaining why the data matches or doesn't match the user query.",
                "report": "If is_relevant is false, output EXACTLY: 'No relevant Python threats found in the database for this query.' If is_relevant is true, output your formatted report using the Threat Summary and Critical Findings structure."
            }
        """)
        
        clean_history = []
        for m in messages:
            if isinstance(m, HumanMessage) or getattr(m, 'type', '') == "tool": 
                clean_history.append(m)
            
        analyzer_messages = [analyzer_prompt] + clean_history
        
        print("\n\n--- [Augmentation Agent: Synthesizing CTI Report] ---")
        response = llm.invoke(analyzer_messages)

        print("\n\n--- [Augmentation Agent: Synthesizing CTI Report] ---")
        response = llm.invoke(analyzer_messages)
        
        # --- NEW JSON PARSING LOGIC ---
        raw_response = response.content
        
        try:
            # Parse the JSON string into a Python dictionary
            parsed_data = json.loads(raw_response)
            
            # Print the AI's reasoning to your terminal
            print("\n" + "="*50)
            print(" 🧠 [LLM VALIDATION GRADER]")
            print(f"    Relevant: {parsed_data.get('is_relevant')}")
            print(f"    Reasoning: {parsed_data.get('reasoning')}")
            print("="*50 + "\n")
            
            # Extract just the report for the Streamlit UI
            final_content = parsed_data.get("report", "Error generating report.")
            
        except json.JSONDecodeError:
            # Fallback just in case the 3B model forgets to output strict JSON
            print("\n[!] Failed to parse JSON. Raw output from LLM:")
            print(raw_response)
            final_content = raw_response

        # Repackage the clean report back into an AIMessage
        final_message = AIMessage(content=final_content)
        # ------------------------------

        print("\n--------------------------------------------------\n")
        
        # =====================================================================
        # 🕵️ PASSIVE VERIFICATION & LOGGING
        # =====================================================================
        # 1. Extract the raw database context that was fed to the LLM
        db_context = "\n".join([m.content for m in clean_history if getattr(m, 'type', '') == "tool"])
        
        # 2. Fire and forget: Run the auditor in a background thread
        # This ensures the UI doesn't freeze while the second LLM checks for hallucinations.
        threading.Thread(
            target=run_verification_and_log,
            args=("Analyzer Agent", "agents.py", db_context, final_content),
            daemon=True
        ).start()
        # =====================================================================

        guardrail_flag = "GUARDRAIL TRIGGERED" in final_content.upper()
        
        step_time = time.time() - t0
        print(f"  🧠 [Analyzer] Report synthesis took {step_time:.2f}s")
        
        return {
            "messages": [final_message],  # <--- Changed this from [response] to [final_message]
            "analysis_time": time.time() - t0,
            "guardrail_triggered": guardrail_flag
        }

    workflow = StateGraph(AgentState)
    
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("analyzer", analyzer_node)
    
    workflow.set_entry_point("researcher")
    
    # Direct edge from researcher to analyzer
    workflow.add_edge("researcher", "analyzer")
    workflow.add_edge("analyzer", END) 
    
    return workflow.compile()
