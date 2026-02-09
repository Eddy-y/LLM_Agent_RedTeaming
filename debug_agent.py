# debug_agent.py
from langchain_core.messages import HumanMessage
from engine import load_tool_capable_model
from src.tools import search_tools
from agents import build_red_team_graph

# 1. Setup
model = load_tool_capable_model("llama3")
model_with_tools = model.bind_tools(search_tools)
agent = build_red_team_graph(model_with_tools, search_tools)

# 2. Interactive Loop
print("\n🤖 Interactive Red Team Agent (Type 'quit' to exit)")
pkg = input("Enter a package to investigate (e.g., flask): ")

state = {
    "messages": [HumanMessage(content=f"Investigate {pkg} and tell me if it is safe.")],
    "package_name": pkg,
    "steps_taken": 0
}

print(f"\n--- Starting Investigation on {pkg} ---")

# 3. Stream the thoughts
for event in agent.stream(state):
    for key, value in event.items():
        if key == "agent":
            msg = value["messages"][0]
            if msg.tool_calls:
                print(f"\n🧠 AGENT: I want to run these tools: {[t['name'] for t in msg.tool_calls]}")
                # This helps you catch hallucinations immediately
            else:
                print(f"\n🗣️ AGENT: {msg.content}")
        elif key == "tools":
            print(f"✅ SYSTEM: Tool executed successfully.")