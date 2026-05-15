"""
graph_agents.py
Houses the LangGraph state machine for the Augmentation Interface.
"""
import time
import json
import threading
from typing import TypedDict, Annotated, Sequence
import operator

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, ToolMessage, AIMessage
from langgraph.graph import StateGraph, END
from src.verifier import run_verification_and_log

# ==========================================
# STATE MANAGEMENT
# ==========================================
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    package_name: str
    steps_taken: int
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
        
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # 2. Build a dynamic SQL query using ILIKE for case-insensitive matching
        query_conditions = " OR ".join(["summary ILIKE %s OR title ILIKE %s" for _ in keywords])
        
        params = []
        for kw in keywords:
            params.extend([f"%{kw}%", f"%{kw}%"]) 
            
        sql = f"SELECT * FROM normalized_items WHERE {query_conditions} LIMIT 10"
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        
        # 3. Always close the connection
        conn.close()
        
        if not rows:
            return f"No records found matching heuristic keywords: {keywords}"
            
        formatted_report = f"Heuristic Database Matches for {keywords}:\n\n"
        for row in rows:
            formatted_report += f"- ID: {row.get('canonical_id')} (Package: {row.get('package_name')}, Severity: {row.get('severity')})\n"
            formatted_report += f"  Summary: {row.get('summary')}\n\n"

        return formatted_report
        
    except Exception as e:
        return f"Database error: {e}"
    
# ==========================================
# LANGGRAPH PIPELINE (DETERMINISTIC RETRIEVAL)
# ==========================================
def build_red_team_graph(llm, tools=None):
    
    def researcher_node(state):
        t0 = time.time()
        
        user_query = state.get('package_name', '') 
        
        stop_words = {"tell", "me", "about", "are", "there", "any", "the", "a", "an", "of", "and", "or", "in", "to", "for"}
        raw_words = user_query.lower().replace("?", "").replace(".", "").split()
        heuristic_keywords = [word for word in raw_words if word not in stop_words and len(word) > 2]
        
        if not heuristic_keywords:
            heuristic_keywords = ["vulnerability"]
            
        raw_cti_data = fetch_local_cti_data(heuristic_keywords)
        step_time = time.time() - t0

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
            1. RELEVANCE CHECK: You must first determine if the database records actually match the user's specific topic.
            2. NO RECOMMENDATIONS: Do not include mitigations or recommendations.
            3. STRICT JSON: You MUST return ONLY a valid JSON object. Do not include markdown formatting like ```json.
            
            OUTPUT FORMAT:
            {
                "is_relevant": true or false,
                "reasoning": "1 sentence explaining why the data matches or doesn't match the user query.",
                "report": "If is_relevant is false, output EXACTLY: 'No relevant Python threats found in the database for this query.' If is_relevant is true, output your formatted report using the Threat Summary and Critical Findings structure."
            }
        """)
        
        clean_history = [m for m in messages if isinstance(m, HumanMessage) or getattr(m, 'type', '') == "tool"]
        analyzer_messages = [analyzer_prompt] + clean_history
        
        response = llm.invoke(analyzer_messages)
        raw_response = response.content
        
        try:
            parsed_data = json.loads(raw_response)
            final_content = parsed_data.get("report", "Error generating report.")
        except json.JSONDecodeError:
            final_content = raw_response

        final_message = AIMessage(content=final_content)
        
        # Background Auditor Thread
        db_context = "\n".join([m.content for m in clean_history if getattr(m, 'type', '') == "tool"])
        threading.Thread(
            target=run_verification_and_log,
            args=("Analyzer Agent", "graph_agents.py", db_context, final_content),
            daemon=True
        ).start()

        guardrail_flag = "GUARDRAIL TRIGGERED" in final_content.upper()
        
        return {
            "messages": [final_message],
            "analysis_time": time.time() - t0,
            "guardrail_triggered": guardrail_flag
        }

    workflow = StateGraph(AgentState)
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("analyzer", analyzer_node)
    workflow.set_entry_point("researcher")
    workflow.add_edge("researcher", "analyzer")
    workflow.add_edge("analyzer", END) 
    
    return workflow.compile()