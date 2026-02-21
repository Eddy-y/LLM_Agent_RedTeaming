from typing import TypedDict, Annotated, Sequence
import operator

from langchain_core.messages import BaseMessage, SystemMessage
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
                You are Agent 1: The Retriever.
                Your ONLY job is to trigger the tool functions.
                
                CRITICAL RULES:
                1. DO NOT write any conversational text.
                2. DO NOT write JSON summaries or reports.
                3. DO NOT guess or hallucinate CVEs.
                4. Immediately invoke the 3 tools: 'check_pypi_metadata', 'check_github_advisories', and 'check_nvd_cves'.
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
        
        # This agent reads the entire history of what Agent 1 did.
        analyzer_prompt = SystemMessage(content="""
            You are Agent 2: The Security Analyzer.
            Read the conversation history and the raw tool outputs gathered by Agent 1.
            
            YOUR JOB: Filter the noise and write a highly accurate Security Report.
            
            CRITICAL RULES:
            1. DISAMBIGUATION: You are analyzing PYTHON packages. If the data references unrelated software (e.g., Xen hypervisors, hardware, C++), IGNORE IT completely.
            2. HIERARCHY OF TRUST: GitHub Advisories are explicitly scoped to Python. If NVD data looks suspicious or ancient, prioritize GitHub data.
            3. Synthesize the valid threats into a structured report.
        """)
        
        # We replace the Retriever's system prompt with the Analyzer's prompt
        analyzer_messages = [analyzer_prompt] + [m for m in messages if not isinstance(m, SystemMessage)]
        
        print("\n\n--- [Agent 2: Analyzing Data & Writing Report] ---")
        # Notice we use the raw `llm` here. No tools bound. It must output text.
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