import torch
from transformers import AutoTokenizer, pipeline, AutoModelForCausalLM
from langchain_ollama import ChatOllama
from langchain_core.callbacks import BaseCallbackHandler


# 1. Define a "Streamer" that prints to console immediately
class TokenStreamer(BaseCallbackHandler):
    def on_llm_new_token(self, token: str, **kwargs) -> None:
        print(token, end="", flush=True)

def load_tool_capable_model(model_name: str = "llama3.2:1b"):
    print(f"🧠 Initializing Agent Brain: {model_name} (with Streaming)...")
    
    llm = ChatOllama(
        model=model_name,
        temperature=0,
        streaming=True,
        callbacks=[TokenStreamer()],
        # --- NEW SETTINGS TO STOP THE LOOP ---
        repeat_penalty=1.3,   # Strongly penalize repeating the same tool call
        stop=["<|eot_id|>", "<|start_header_id|>"], # Force Llama 3 to stop generating
    )
    
    return llm