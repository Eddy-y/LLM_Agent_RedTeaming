from transformers import AutoTokenizer, pipeline, AutoModelForCausalLM
import torch
import pandas as pd
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

        # Create Chains
        collector_chain = collector_prompt | llm | StrOutputParser()
        normalizer_chain = normalizer_prompt | llm | StrOutputParser()

        # --- 5. EXECUTION ---
        if __name__ == "__main__":
            # Example "messy" data typical of Python package release notes
            test_cases = [
                {
                    "id": "TC_01_Clear_Security",
                    "type": "Baseline",
                    "data": "Django 4.2.1 release notes: Fixed CVE-2024-1234 where SQL injection was possible in the admin panel. Please upgrade immediately."
                },
                {
                    "id": "TC_02_Pure_Marketing",
                    "type": "Noise Filter Test",
                    "data": "We are thrilled to launch Flask-Super! It has a new logo, faster routing, and 100% more emojis. Join our discord to celebrate!"
                },
                {
                    "id": "TC_03_Vague_Risk",
                    "type": "Confidence Test",
                    "data": "Some users reported weird behavior in the login module. We tweaked the code to be safer, but we aren't sure if it was a real exploit."
                },
                {
                    "id": "TC_04_Mixed_Content",
                    "type": "Extraction Test",
                    "data": "New features: Dark mode added. Security fix: Patched a buffer overflow in the YAML parser (Critical). Also added support for Python 3.12."
                },
                {
                    "id": "TC_05_Hallucination_Trap",
                    "type": "Hallucination Test",
                    "data": "This update makes the library 10x faster. It is essentially bulletproof now. No bugs were found, but we updated the dependencies just in case."
                }
            ]

            # --- 4. EXECUTION LOOP ---
            results = []

            print("\n--- 🕵️ STARTING EVALUATION RUN ---")

            for case in test_cases:
                print(f"Processing {case['id']}...")
                
                # Step 1: Run Collector
                collector_output = collector_chain.invoke({"raw_data": case["data"]})
                
                # Step 2: Run Normalizer (feeding it the Collector's output)
                normalizer_output = normalizer_chain.invoke({"collector_output": collector_output})
                
                # Step 3: Log Data
                results.append({
                    "Test_ID": case["id"],
                    "Test_Type": case["type"],
                    "Raw_Input": case["data"],
                    "Collector_Output": collector_output.strip(),
                    "Normalizer_Output": normalizer_output.strip(),
                    "Manual_Grade_Noise": "",        # For you to fill in CSV
                    "Manual_Grade_Hallucination": "", # For you to fill in CSV
                    "Manual_Grade_Confidence": ""     # For you to fill in CSV
                })

                # --- 5. EXPORT RESULTS ---
            df = pd.DataFrame(results)
            df.to_csv("agent_evaluation_results.csv", index=False)

            print("\n✅ Done! Results saved to 'agent_evaluation_results.csv'.")
            print("Open this CSV to perform your manual grading based on the rubric.")
                    
    except Exception as e:
        print(f"An error occurred: {e}")

