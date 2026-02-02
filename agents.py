from typing import TypedDict, Annotated, Sequence
import operator

from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

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
        # The agent decides the next move
        response = llm.invoke(messages)
        # We return the update to the state
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
        
        # If the LLM wants to run a tool, go to 'tools'
        if last_message.tool_calls:
            return "tools"
        # Otherwise, stop
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