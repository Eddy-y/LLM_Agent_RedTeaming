import json
import os
from pathlib import Path

STATE_FILE = Path("data/pipeline_state.json")

def load_state():
    if not os.path.exists(STATE_FILE):
        return {"mitre_offset": 0, "capec_offset": 0}
    with open(STATE_FILE, "r") as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def advance_mitre_offset(batch_size):
    state = load_state()
    state["mitre_offset"] = state.get("mitre_offset", 0) + batch_size
    save_state(state)

def advance_capec_offset(batch_size):
    state = load_state()
    state["capec_offset"] = state.get("capec_offset", 0) + batch_size
    save_state(state)
    