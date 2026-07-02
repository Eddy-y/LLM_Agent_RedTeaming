import traceback
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import time
import json
from psycopg2 import extras
from langchain_core.messages import HumanMessage
from langchain_aws import ChatBedrock
from src.config import get_settings
from src.db import get_db_connection, release_db_connection
from graph_agents import build_red_team_graph

settings = get_settings()
llm = ChatBedrock(model_id=settings.bedrock_model_id, region_name="us-east-1", credentials_profile_name=settings.aws_profile_name)
agent_app = build_red_team_graph(llm)

app = FastAPI(title="CTI API", version="2.0")

class ReportRequest(BaseModel):
    package_name: str
    prompt: str = ""

@app.post("/generate_report_stream")
async def generate_report_stream(request: Request):
    data = await request.json()
    package_name = data.get("package_name")
    custom_prompt = data.get("prompt", "")
    
    initial_state = {
        "messages": [HumanMessage(content=custom_prompt or f"Analyze {package_name}")],
        "package_name": package_name,
        "steps_taken": 0
    }
    
    def event_generator():
        final_report = ""
        guardrail_active = False
        
        try:
            # Consume chunks natively from the compiled LangGraph workflow app
            for chunk in agent_app.stream(initial_state):
                for node_name, node_output in chunk.items():
                    # Stream the current active node step back to the UI log tracker
                    yield f"data: {json.dumps({'event': node_name})}\n\n"
                    
                    # Capture the report content if the analyzer node runs
                    if node_name == "analyzer" and "messages" in node_output:
                        final_report = node_output["messages"][-1].content
                        guardrail_active = node_output.get("guardrail_triggered", False)
                        
                    # Capture the override message if the safety guardrail node triggers
                    elif node_name == "interception_node" and "messages" in node_output:
                        final_report = node_output["messages"][-1].content
                        guardrail_active = True

            # 🚀 Crucial: Send the explicit 'complete' event that the Streamlit UI expects to render
            if final_report:
                yield f"data: {json.dumps({'event': 'complete', 'payload': {'report': final_report, 'guardrail_triggered': guardrail_active}})}\n\n"
            else:
                yield f"data: {json.dumps({'event': 'complete', 'payload': {'report': 'Analysis complete. No threat entries required modification.', 'guardrail_triggered': False}})}\n\n"
                
        except Exception as e:
            # Tracebacks will now ONLY print if an actual runtime exception occurs
            import traceback
            print("\n🚨 ACTUAL STREAM EXECUTION CRASH:")
            traceback.print_exc()
            yield f"data: {json.dumps({'event': 'error', 'payload': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/v1/metrics")
def get_metrics():
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute("SELECT * FROM graph_execution_metrics ORDER BY evaluated_at DESC LIMIT 50")
        return cur.fetchall()
    finally:
        release_db_connection(conn)

@app.get("/api/v1/threats")
def get_threats(limit: int = 50, offset: int = 0):
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute("SELECT * FROM threat_intelligence_records ORDER BY published_at DESC NULLS LAST LIMIT %s OFFSET %s", (limit, offset))
        return cur.fetchall()
    finally:
        release_db_connection(conn)

@app.get("/api/v1/audits")
def get_audits():
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute("SELECT * FROM url_validation_logs ORDER BY timestamp DESC LIMIT 50")
        return cur.fetchall()
    finally:
        release_db_connection(conn)