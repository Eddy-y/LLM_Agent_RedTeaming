import torch
from transformers import AutoTokenizer, pipeline, AutoModelForCausalLM

def load_optimized_pipeline(model_id):
    """
    Detects hardware and returns the most optimized pipeline available.
    Priority: CUDA (NVIDIA) -> OpenVINO (Intel) -> MPS (Mac) -> CPU
    """
    print(f"⚙️ Initializing {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)

    # Common settings to prevent "run-on" text and hallucinated exercises
    pipeline_kwargs = {
        "tokenizer": tokenizer,
        "max_new_tokens": 300,       # Limit output length
        "return_full_text": False,   # Don't repeat the prompt in the output
        "pad_token_id": tokenizer.eos_token_id,
        "eos_token_id": tokenizer.eos_token_id
    }

    # --- 1. NVIDIA GPU (CUDA) ---
    if torch.cuda.is_available():
        print(f"🚀 Acceleration: NVIDIA CUDA detected ({torch.cuda.get_device_name(0)})")
        model = AutoModelForCausalLM.from_pretrained(
            model_id, 
            torch_dtype=torch.float16, 
            trust_remote_code=False
        )
        # Fix: Pass device=0 directly here
        return pipeline("text-generation", model=model, device=0, **pipeline_kwargs)

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
        # OpenVINO handles devices internally, so we don't pass 'device'
        return pipeline("text-generation", model=model, **pipeline_kwargs)
        
    except ImportError:
        pass # Fall through if library is missing
    except Exception as e:
        print(f"⚠️ OpenVINO optimization failed: {e}")
        print("🔄 Falling back to standard CPU execution.")

    # --- 3. Apple Silicon (MPS) & Standard CPU Fallback ---
    if torch.backends.mps.is_available():
        print("🍎 Acceleration: Apple MPS detected.")
        device = "mps"
    else:
        print("🐢 Loading model on Standard CPU...")
        device = "cpu"

    # Load standard model for Mac/CPU
    model = AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=False)

    return pipeline("text-generation", model=model, device=device, **pipeline_kwargs)