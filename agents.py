from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

def get_agent_chains(llm):
    # --- AGENT 1: THE COLLECTOR ---
    # Goal: Read raw text and extract *anything* security relevant.
    # Change: Removed "single line" constraint to allow capturing complex, messy details.
    collector_template = """Instruct: You are a Security Data Collector. Your job is to filter noise and extract security-relevant information from unstructured text.
    
    If the text contains potential security issues (vulnerabilities, warnings, CVEs, risky dependencies), extract the relevant sentences exactly as they appear.
    If the text is purely marketing, UI updates, or unrelated to security, output "NO_SECURITY_SIGNAL".

    Raw Input:
    {raw_data}

    ###
    Constraint: Do not summarize. Do not create a bulleted list. Return only the relevant text excerpts joined by newlines.
    Collector Output:"""

    collector_prompt = PromptTemplate(
        input_variables=["raw_data"],
        template=collector_template
    )

    # --- AGENT 2: THE NORMALIZER ---
    # Goal: Organize the output, group issues, and assign confidence[cite: 22, 31].
    # Change: Asks for a LIST of objects (to handle multiple issues) and adds "Category" to see how it groups them on its own.
    normalizer_template = """Instruct: You are a Security Normalizer. You will receive a set of unorganized security excerpts. 
    Your goal is to normalize this into a structured JSON format. 
    
    You must determine the "Category" yourself (e.g., "Critical Vulnerability", "Minor Warning", "Dependency Issue", etc.).
    
    Input Text:
    {collector_output}

    ###
    Constraint: Return ONLY a valid JSON object containing a list of findings. Do not include markdown formatting (like ```json). 
    
    Required JSON Structure:
    {{
        "analysis_summary": "Brief overview of what was found",
        "findings": [
            {{
                "issue_type": "Short name of the issue",
                "category": "Your categorization",
                "confidence_score": "1-10",
                "confidence_reasoning": "Why are you confident? (e.g., 'Explicit CVE ID found' or 'Vague wording')",
                "original_evidence": "The specific text text that supports this"
            }}
        ]
    }}
    
    Normalizer Output:"""

    normalizer_prompt = PromptTemplate(
        input_variables=["collector_output"],
        template=normalizer_template
    )
    
    # --- CHAINS ---
    # We keep the chains simple to isolate behavior for evaluation.
    chains = {
        "collector": collector_prompt | llm | StrOutputParser(),
        "normalizer": normalizer_prompt | llm | StrOutputParser()
    }

    return chains