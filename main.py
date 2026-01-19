from transformers import AutoTokenizer, pipeline, AutoModelForCausalLM
import torch
from langchain_huggingface import HuggingFacePipeline
from langchain_core.prompts import PromptTemplate 
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough


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
    # We use a nested try-except block here. If the model can't be converted, we catch the error.
    try:
        from optimum.intel import OVModelForCausalLM
        print("🚀 Acceleration: Attempting Intel OpenVINO optimization...")
        
        # Try to load and export. If this fails (like with phi-msft), it jumps to 'except'
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
        # Standard CPU Fallback
        device = "cpu"

    # --- 4. Standard Fallback ---
    print(f"🐢 Loading model on {device.upper()} (Standard Mode)...")
    return pipeline(
        "text-generation", 
        model=model_id, 
        device=device, 
        trust_remote_code=True
    )

# --- Main Execution ---
if __name__ == "__main__":
    #model_id = "NickyNicky/dolphin-2_6-phi-2_oasst2_chatML_V2"

    try:
        # We use Microsoft Phi-2 as it is small, capable of reasoning, and hardware-friendly
        model_id = "microsoft/phi-2" 
        hf_pipe = load_optimized_pipeline(model_id)
        llm = HuggingFacePipeline(pipeline=hf_pipe)

        # --- 3. AGENT PROMPT DESIGN (The Core Research) ---

        # AGENT 1: THE COLLECTOR
        # Goal: Extract security signals from noise.
        collector_prompt = PromptTemplate(
            input_variables=["raw_data"],
            template="""Instruct: You are a Security Data Collector Agent. 
        Your goal is to read the raw text below and extract ONLY information related to security vulnerabilities, patches, or risks in Python packages (Flask, Django, etc.).
        Ignore marketing fluff, unrelated code updates, or general news.

        Raw Data:
        {raw_data}

        Output:
        Provide a bulleted list of the specific security findings. If none, state "No security data found."
        Output:"""
        )

        # AGENT 2: THE NORMALIZER
        # Goal: Structure the data and assign confidence.
        normalizer_prompt = PromptTemplate(
            input_variables=["collector_output"],
            template="""Instruct: You are a Security Data Normalizer Agent.
        Your input is a list of findings from a Collector Agent. 
        Your task is to:
        1. Standardize this into a structured format (JSON-like).
        2. Assign a "Confidence Score" (Low/Medium/High) based on how specific the details are.
        3. Flag if the Collector seemed to be hallucinating (e.g., vague claims without version numbers).

        Collector Input:
        {collector_output}

        Output:
        Provide the final structured report.
        Output:"""
        )

        # --- 4. BUILDING THE CHAIN ---
        # Flow: Raw Data -> Collector -> (pass to) Normalizer -> Final Output

        # Chain 1: Collector runs
        collector_chain = collector_prompt | llm | StrOutputParser()

        # Chain 2: Normalizer runs on Collector's output
        # We use a functional chain where the output of the first step is passed as 'collector_output' to the second
        full_chain = (
            {"collector_output": collector_chain} 
            | normalizer_prompt 
            | llm 
            | StrOutputParser()
        )

        # --- 5. EXECUTION ---
        if __name__ == "__main__":
            # Example "messy" data typical of Python package release notes
            messy_data = """
            We are excited to announce version 4.2! This release includes a new logo and better dark mode support. 
            Also, we fixed a critical issue where untrusted inputs in the YAML parser could lead to arbitrary code execution (CVE-2024-XXXX). 
            Thanks to user @dev123 for the PR. In other news, our annual conference is coming up next month!
            """

            print("\n--- 🕵️ RUNNING AGENT SIMULATION ---")
            print(f"Input Data: {messy_data[:100]}...\n")
            
            # Run the full chain
            # Note: To debug, you can run just collector_chain.invoke({"raw_data": messy_data})
            result = full_chain.invoke({"raw_data": messy_data})
            
            print("--- 📝 FINAL NORMALIZER REPORT ---")
            print(result)
        
    except Exception as e:
        print(f"An error occurred: {e}")

