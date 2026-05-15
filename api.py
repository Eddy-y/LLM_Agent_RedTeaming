from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time
from langchain_core.messages import HumanMessage

# 1. Import your graph builder function from your agents file
from agents import build_red_team_graph

# 2. Initialize your LLM. 
# (Copy exactly how you initialize the 'llm' variable inside your chat_UI.py file. 
# Assuming you are using LangChain's ChatBedrock, it looks something like this:)
from langchain_aws import ChatBedrock
from src.config import get_settings

llm = ChatBedrock(
    model_id="meta.llama3-8b-instruct-v1:0",
    region_name="us-east-1",
    credentials_profile_name=get_settings().aws_profile_name
)

# 3. Build and compile the app right here!
agent_app = build_red_team_graph(llm)

app = FastAPI(title="CTI Augmentation API", version="1.0")

class ReportRequest(BaseModel):
    package_name: str

class ReportResponse(BaseModel):
    package_name: str
    report: str
    execution_time_seconds: float

@app.post("/generate_report", response_model=ReportResponse)
def generate_report(request: ReportRequest):
    """
    Triggers the LangGraph agent to synthesize a report for the requested package.
    """
    start_time = time.time()
    
    initial_state = {
        "messages": [HumanMessage(content=f"Analyze the threat intelligence for the package: {request.package_name}. Generate a mitigation report.")],
        "package_name": request.package_name,
        "steps_taken": 0
    }
    
    try:
        # Trigger the compiled LangGraph execution
        final_state = agent_app.invoke(initial_state)
        
        # Extract the final message from the LLM
        final_report = final_state['messages'][-1].content
        execution_time = round(time.time() - start_time, 2)
        
        return ReportResponse(
            package_name=request.package_name,
            report=final_report,
            execution_time_seconds=execution_time
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))