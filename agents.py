from typing import TypedDict, Annotated, Sequence
import operator

from langchain_core.messages import BaseMessage, SystemMessage, AIMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

# 1. Define the Memory State (KEPT)
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    package_name: str
    steps_taken: int

MAX_STEPS = 6

# 2. Define the Agent Builder Function
def build_red_team_graph(llm, tools):
    """
    Constructs a Multi-Agent StateGraph for Local CTI Augmentation.
    """
    # Give tools ONLY to the Retriever
    researcher_llm = llm.bind_tools(tools)
    
    # --- AGENT 1: THE RETRIEVER (Local DB Scout) ---
    def researcher_node(state):
        messages = state['messages']
        
        if not isinstance(messages[0], SystemMessage):
            # REFACTORED: Now focuses entirely on querying your local normalized DB.
            sys_prompt = SystemMessage(content="""
            You are a CTI Data Retriever. 
            
            YOUR GOAL: Execute tools to find threat intelligence data related to the requested package from our local, normalized SQLite database.
            
            CRITICAL RULES:
            1. DO NOT hallucinate results. You cannot "guess" what the database contains.
            2. TO USE A TOOL: You must strictly generate a "Tool Call".
            3. PARAMETERS: You MUST provide the 'package_name' parameter for every tool.
            4. Once you have called the tools and received the data, your job is completely done. Stop generating text.
            
            Valid Tools:
            - search_local_cti(package_name=str)
        """)
            messages = [sys_prompt] + messages
            
        response = researcher_llm.invoke(messages)
        
        return {
            "messages": [response], 
            "steps_taken": state.get("steps_taken", 0) + 1
        }

    # --- ACTION NODE: TOOLS --- (KEPT)
    tool_node = ToolNode(tools)

    # --- AGENT 2: THE AUGMENTATION AGENT (The Detective) ---
    def analyzer_node(state):
        messages = state['messages']
        
        # REFACTORED: This is now the "Explain-the-link" step your professor asked for.
        analyzer_prompt = SystemMessage(content="""
            You are a Cyber Threat Intelligence (CTI) Augmentation Agent. 
            The user asked about a specific software package. 
            
            YOUR JOB: Read the retrieved records (CVEs, Advisories, CAPEC patterns, ATT&CK techniques) from our local database, and connect the dots.
            
            CRITICAL RULES:
            1. STRICT GROUNDING: ONLY use the provided text from the tool outputs. Do not invent vulnerabilities.
            2. THE AUGMENTATION STEP: You must propose short, high-level "bridge statements" connecting isolated facts. (e.g., Explain why a CVE flaw found in this package is likely to enable a specific CAPEC attack pattern or ATT&CK technique found in the database).
            3. COHERENT THREAT PICTURE: Format your response into a clear, readable Markdown report:
               - Executive Summary
               - Known Vulnerabilities (CVEs & Advisories)
               - Linked Attack Patterns (CAPEC) & Behaviors (ATT&CK)
               - Synthesized Threat Picture (Your bridge statements explaining the links)
        """)
        
        # KEPT: Filter out Agent 1's non-tool text
        clean_history = []
        for m in messages:
            # Keep the user's initial request
            if isinstance(m, HumanMessage):
                clean_history.append(m)
            # ONLY keep the raw data that came out of the SQLite tool
            elif getattr(m, 'type', '') == "tool": 
                clean_history.append(m)
            # Completely ignore anything Agent 1 tried to say/hallucinate
            
        analyzer_messages = [analyzer_prompt] + clean_history
        
        print("\n\n--- [Augmentation Agent: Synthesizing CTI Report] ---")
        response = llm.invoke(analyzer_messages)
        print("\n--------------------------------------------------\n")
        
        return {"messages": [response]}

    # --- ROUTER LOGIC --- (KEPT)
    def should_continue(state):
        messages = state['messages']
        last_message = messages[-1]
        steps = state.get('steps_taken', 0)
        
        if steps >= MAX_STEPS:
            print(f"  🛑 [Limit Reached]: Forcing analysis after {steps} steps.")
            return "analyzer"
        
        if last_message.tool_calls:
            return "tools"
            
        return "analyzer"

    # --- BUILD GRAPH --- (KEPT)
    workflow = StateGraph(AgentState)
    
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("tools", tool_node)
    workflow.add_node("analyzer", analyzer_node)
    
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
    workflow.add_edge("analyzer", END) 
    
    return workflow.compile()
