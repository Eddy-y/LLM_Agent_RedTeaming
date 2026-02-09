from typing import TypedDict, Annotated, Sequence
import operator

from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import SystemMessage 

MAX_STEPS = 3

# 1. Define the Memory State
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    package_name: str
    steps_taken: int

# 2. Define the Agent Builder Function
def build_red_team_graph(llm, tools):
    """
    Constructs the StateGraph for the Red Teaming Agent.
    Args:
        llm: The tool-capable ChatModel (already bound with tools).
        tools: List of tool functions.
    Returns:
        Compiled Graph (app).
    """
    
    # --- NODE A: REASONING (The Agent) ---
    def call_model(state):
        messages = state['messages']
        
        # 1. INJECT SYSTEM PROMPT IF MISSING
        # This forces the model to remember the EXACT tool names
        if not isinstance(messages[0], SystemMessage):
            system_prompt = SystemMessage(content="""
            You are a Security Agent. You are NOT a writer. You are an OPERATOR.
            
            YOUR GOAL: Execute tools to find real data.
            
            CRITICAL RULES:
            1. DO NOT hallucinate results. You cannot "guess" what the database contains.
            2. DO NOT write JSON text like '{"function": ...}'. 
            3. TO USE A TOOL: You must strictly generate a "Tool Call".
            4. PARAMETERS: You MUST provide the 'package_name' parameter for every tool.
               - WRONG: check_pypi_metadata()
               - CORRECT: check_pypi_metadata(package_name="flask")
            
            Valid Tools:
            - check_pypi_metadata(package_name=str)
            - check_github_advisories(package_name=str)
            - check_nvd_cves(package_name=str)
        """)
            messages = [system_prompt] + messages
            
        print("\n\n--- [Generating Response] ---") # Visual separator
        response = llm.invoke(messages)
        print("\n-----------------------------\n")
        #STOPS HERE FOR SOME REASON.

        return {
            "messages": [response], 
            "steps_taken": state.get("steps_taken", 0) + 1
        }

    # --- NODE B: ACTION (The Tools) ---
    tool_node = ToolNode(tools)

    # --- CONDITIONAL LOGIC ---
    def should_continue(state):
        messages = state['messages']
        last_message = messages[-1]
        steps = state.get('steps_taken', 0)
        
        # 1. SAFETY BREAK: Stop if we've exceeded the limit
        if steps >= MAX_STEPS:
            print(f"  🛑 [Limit Reached]: Stopping after {steps} steps.")
            return END

        # 2. Standard Logic: If tool call, go to tools
        if last_message.tool_calls:
            return "tools"
        
        # 3. Otherwise, stop
        return END

    # --- BUILD GRAPH ---
    workflow = StateGraph(AgentState)
    workflow.add_node("agent", call_model)
    workflow.add_node("tools", tool_node)
    
    workflow.set_entry_point("agent")
    
    workflow.add_conditional_edges(
        "agent",
        should_continue,
        {
            "tools": "tools",
            END: END
        }
    )
    workflow.add_edge("tools", "agent") # Loop back to reason about the tool output
    
    return workflow.compile()