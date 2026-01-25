import pandas as pd
from langchain_huggingface import HuggingFacePipeline

# Import your custom modules
# Ensure engine.py and agents.py are in the same directory
from engine import load_optimized_pipeline
from agents import get_agent_chains

# --- CONFIGURATION ---
MODEL_ID = "microsoft/phi-2"
OUTPUT_FILE = "outputs/agent_evaluation_results3.csv"

# --- TEST DATA ---
TEST_CASES = [
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
    # {
    #     "id": "TC_03_Vague_Risk",
    #     "type": "Confidence Test",
    #     "data": "Some users reported weird behavior in the login module. We tweaked the code to be safer, but we aren't sure if it was a real exploit."
    # },
    # {
    #     "id": "TC_04_Mixed_Content",
    #     "type": "Extraction Test",
    #     "data": "New features: Dark mode added. Security fix: Patched a buffer overflow in the YAML parser (Critical). Also added support for Python 3.12."
    # },
    # {
    #     "id": "TC_05_Hallucination_Trap",
    #     "type": "Hallucination Test",
    #     "data": "This update makes the library 10x faster. It is essentially bulletproof now. No bugs were found, but we updated the dependencies just in case."
    # }
]

def main():
    print(f"🚀 Starting Agent Evaluation System using {MODEL_ID}...")

    # 1. INITIALIZE ENGINE (Hardware Detection & Model Loading)
    try:
        # Calls the function from engine.py
        hf_pipe = load_optimized_pipeline(MODEL_ID)
        llm = HuggingFacePipeline(pipeline=hf_pipe)
    except Exception as e:
        print(f"❌ Critical Error: Failed to load model. {e}")
        return

    # 2. INITIALIZE AGENTS (Prompts & Chains)
    # Calls the function from agents.py
    chains = get_agent_chains(llm)
    collector_chain = chains['collector']
    normalizer_chain = chains['normalizer']

    results = []
    print("\n--- 🕵️ RUNNING TEST BATCH ---")

    # 3. EXECUTION LOOP
    for case in TEST_CASES:
        print(f"Processing Case: {case['id']}...")
        
        try:
            # Step A: Run Collector Agent
            collector_output = collector_chain.invoke({"raw_data": case["data"]})
            
            # Step B: Run Normalizer Agent (Input is Collector's Output)
            normalizer_output = normalizer_chain.invoke({"collector_output": collector_output})
            
            # Step C: Log Results
            results.append({
                "Test_ID": case["id"],
                "Test_Type": case["type"],
                "Raw_Input": case["data"],
                "Collector_Output": collector_output.strip(),
                "Normalizer_Output": normalizer_output.strip(),
                "Manual_Grade_Noise": "",        # Placeholder for manual review
                "Manual_Grade_Hallucination": "",
                "Manual_Grade_Confidence": ""
            })
            
        except Exception as e:
            print(f"⚠️ Error processing {case['id']}: {e}")
            # We continue to the next case even if one fails

    # 4. EXPORT RESULTS
    if results:
        df = pd.DataFrame(results)
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n✅ Success! Results written to: {OUTPUT_FILE}")
    else:
        print("\n⚠️ Warning: No results were generated.")

if __name__ == "__main__":
    main()