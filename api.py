"""
api.py
FastAPI backend for the Multi-Agent CTI Pipeline.
Hosts the LangGraph Augmentation Agent as a REST API.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time
from langchain_core.messages import HumanMessage
from langchain_aws import ChatBedrock

# --- Local Imports ---
from src.config import get_settings
from src.metrics import log_metric
from graph_agents import build_red_team_graph 


# --- Initialize AWS Bedrock LLM ---
llm = ChatBedrock(
    model_id="meta.llama3-8b-instruct-v1:0",
    region_name="us-east-1",
    credentials_profile_name=get_settings().aws_profile_name
)

# --- Compile the LangGraph Application ---
agent_app = build_red_team_graph(llm)

app = FastAPI(title="CTI Augmentation API", version="1.0")

# --- Pydantic Models ---
class ReportRequest(BaseModel):
    package_name: str

class MetricsData(BaseModel):
    retrieval_latency: float
    analysis_latency: float
    total_latency: float
    cves_correlated: int
    mitre_capec_linked: int
    guardrail_triggered: bool
    total_steps: int

class ReportResponse(BaseModel):
    package_name: str
    report: str
    tools_used: str
    execution_time_seconds: float
    metrics: MetricsData

@app.post("/generate_report", response_model=ReportResponse)
def generate_report(request: ReportRequest):
    """
    Triggers the LangGraph agent to synthesize a report for the requested package,
    tracks research metrics, and returns the final mitigation strategy.
    """
    package = request.package_name
    print(f"\n========================================")
    print(f"🕵️ Investigating Package: {package}")
    print(f"========================================")
    
    t0_total = time.time()
    
    initial_state = {
        "messages": [HumanMessage(content=f"Analyze the threat intelligence for the package: {package}. Generate a mitigation report.")],
        "package_name": package,
        "steps_taken": 0,
        "start_time": t0_total,
        "retrieval_time": 0.0,
        "analysis_time": 0.0,
        "guardrail_triggered": False
    }
    
    try:
        # 1. Trigger the compiled LangGraph execution
        final_state = agent_app.invoke(initial_state)
        total_time = round(time.time() - t0_total, 2)
        
        # 2. Extract final report
        last_message = final_state['messages'][-1].content
        
        # 3. Calculate Heuristic Metrics
        cves_found = last_message.count("CVE-")
        mitre_capec_linked = last_message.count("CAPEC") + last_message.count("T1") 
        
        metric_data = {
            "package_target": package,
            "retrieval_latency": final_state.get("retrieval_time", 0.0),
            "analysis_latency": final_state.get("analysis_time", 0.0),
            "total_latency": total_time,
            "cves_correlated": cves_found,
            "mitre_capec_linked": mitre_capec_linked,
            "guardrail_triggered": final_state.get("guardrail_triggered", False),
            "total_steps": final_state.get("steps_taken", 0)
        }
        
        # Write to our research metrics (moving to RDS/CloudWatch in Phase 4)
        log_metric(metric_data)
        print(f"📊 Metrics Logged: {metric_data}")

        # 4. Extract clean tool data (What context did the agent actually see?)
        tool_messages = [m for m in final_state['messages'] if getattr(m, 'type', '') == "tool"]
        clean_tool_data = "\n\n---\n\n".join([m.content for m in tool_messages])
        
        if not clean_tool_data:
            clean_tool_data = "No local CTI data was fetched."
            
        return ReportResponse(
            package_name=package,
            report=last_message,
            tools_used=clean_tool_data,
            execution_time_seconds=total_time,
            metrics=MetricsData(**metric_data)
        )

    except Exception as e:
        print(f"[!] Error generating report for {package}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")