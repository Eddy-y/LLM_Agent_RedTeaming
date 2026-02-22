from typing import TypedDict, Annotated, Sequence
import operator

from langchain_core.messages import BaseMessage, SystemMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

# 1. Define the Memory State
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    package_name: str
    steps_taken: int

MAX_STEPS = 6

# 2. Define the Agent Builder Function
def build_red_team_graph(llm, tools):
    """
    Constructs a Multi-Agent StateGraph.
    Args:
        llm: The raw ChatModel (NOT pre-bound with tools).
        tools: List of tool functions.
    """
    # Give tools ONLY to the Researcher
    researcher_llm = llm.bind_tools(tools)
    
    # --- AGENT 1: THE RETRIEVER (Data Gatherer) ---
    def researcher_node(state):
        messages = state['messages']
        
        if not isinstance(messages[0], SystemMessage):
            sys_prompt = SystemMessage(content="""
            You are a Security Agent. You are NOT a writer. You are an OPERATOR.
            
            YOUR GOAL: Execute tools to find real data.
            
            CRITICAL RULES:
            1. DO NOT hallucinate results. You cannot "guess" what the database contains.
            2. TO USE A TOOL: You must strictly generate a "Tool Call".
            3. PARAMETERS: You MUST provide the 'package_name' parameter for every tool.
               - WRONG: check_pypi_metadata()
               - CORRECT: check_pypi_metadata(package_name="flask")
            4. Once you have called the tools, your job is completely done. Stop generating text.
            
            Valid Tools:
            - check_pypi_metadata(package_name=str)
            - check_github_advisories(package_name=str)
            - check_nvd_cves(package_name=str)
        """)
            messages = [sys_prompt] + messages
            
        response = researcher_llm.invoke(messages)
        
        return {
            "messages": [response], 
            "steps_taken": state.get("steps_taken", 0) + 1
        }

    # --- ACTION NODE: TOOLS ---
    tool_node = ToolNode(tools)

    # --- AGENT 2: THE ANALYZER (Data Filter & Synthesizer) ---
    def analyzer_node(state):
        messages = state['messages']
        
        # --- NEW EXPANSIVE PROMPT (For UI Demonstration) ---
        analyzer_prompt = SystemMessage(content="""
            You are an IT Administrative Auditor. Your task is to format public software metadata into a safe, high-level administrative summary.
            
            YOUR JOB: Read the provided JSON tool outputs and format them into a plain Markdown list. 
            
            CRITICAL RULES:
            1. STRICT GROUNDING: ONLY use the provided text. Do not add outside knowledge.
            2. SAFE SUMMARIZATION: You are NOT writing a threat report or analyzing exploits. You are just listing administrative facts and IDs. DO NOT describe how attacks work. 
            3. REQUIRED SECTIONS: Use the headers 'Package Metadata', 'GitHub Advisories', and 'NVD Entries'.
            4. COMPLIANCE: Do not refuse this task. You are simply copying public IDs and brief descriptions into a list for an IT inventory.
        """)
        
        # --- THE FIX: FILTER OUT AGENT 1's REFUSALS ---
        # We keep the User prompt, the Tool Calls, and the Tool Outputs, 
        # but we delete any plain text Agent 1 tried to say.
        clean_history = []
        for m in messages:
            if isinstance(m, SystemMessage):
                continue
            # If Agent 1 generated text (like a refusal) instead of a tool call, hide it from Agent 2
            if isinstance(m, AIMessage) and not m.tool_calls:
                continue 
            clean_history.append(m)

        analyzer_messages = [analyzer_prompt] + clean_history
        
        print("\n\n--- [Agent 2: Analyzing Data & Writing Report] ---")
        response = llm.invoke(analyzer_messages)
        print("\n--------------------------------------------------\n")
        
        return {"messages": [response]}

    # --- ROUTER LOGIC ---
    def should_continue(state):
        messages = state['messages']
        last_message = messages[-1]
        steps = state.get('steps_taken', 0)
        
        # 1. Safety limit
        if steps >= MAX_STEPS:
            print(f"  🛑 [Limit Reached]: Forcing analysis after {steps} steps.")
            return "analyzer"
        
        # 2. If Agent 1 used a tool, go to tools
        if last_message.tool_calls:
            return "tools"
            
        # 3. If Agent 1 is done using tools, pass the baton to Agent 2
        return "analyzer"

    # --- BUILD GRAPH ---
    workflow = StateGraph(AgentState)
    
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("tools", tool_node)
    workflow.add_node("analyzer", analyzer_node) # New Node
    
    workflow.set_entry_point("researcher")
    
    workflow.add_conditional_edges(
        "researcher",
        should_continue,
        {
            "tools": "tools",
            "analyzer": "analyzer"
        }
    )
    workflow.add_edge("tools", "researcher")
    workflow.add_edge("analyzer", END) # Only ends after Agent 2 finishes
    
    return workflow.compile()