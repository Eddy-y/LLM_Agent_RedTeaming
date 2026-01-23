import torch
from transformers import AutoTokenizer, pipeline, AutoModelForCausalLM

def load_optimized_pipeline(model_id):
    """
    Detects hardware and returns the most optimized pipeline available.
    Priority: CUDA (NVIDIA) -> OpenVINO (Intel) -> MPS (Mac) -> CPU
    """
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)

    # --- 1. NVIDIA GPU (CUDA) ---
    if torch.cuda.is_available():
        print(f"🚀 Acceleration: NVIDIA CUDA detected ({torch.cuda.get_device_name(0)})")
        model = AutoModelForCausalLM.from_pretrained(
            model_id, 
            torch_dtype=torch.float16, 
            trust_remote_code=True
        )
        return pipeline("text-generation", model=model, tokenizer=tokenizer, device=0)

    # --- 2. Intel OpenVINO (Integrated Graphics / CPU) ---
    try:
        from optimum.intel import OVModelForCausalLM
        print("🚀 Acceleration: Attempting Intel OpenVINO optimization...")
        
        model = OVModelForCausalLM.from_pretrained(
            model_id, 
            export=True, 
            trust_remote_code=True
        )
        print("✅ OpenVINO optimization successful.")
        return pipeline("text-generation", model=model, tokenizer=tokenizer)
        
    except Exception as e:
        print(f"⚠️ OpenVINO optimization failed for this specific model: {e}")
        print("🔄 Falling back to standard CPU execution (Slower, but compatible).")

    # --- 3. Apple Silicon (MPS) ---
    if torch.backends.mps.is_available():
        print("🍎 Acceleration: Apple MPS detected.")
        device = "mps"
    else:
        device = "cpu"

    # --- 4. Standard Fallback ---
    print(f"🐢 Loading model on {device.upper()} (Standard Mode)...")
    return pipeline(
        "text-generation", 
        model=model_id, 
        device=device, 
        tokenizer=tokenizer, 
        max_new_tokens=150,
        return_full_text=False, # Important: Don't repeat the prompt
        pad_token_id=tokenizer.eos_token_id
    )
