from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from typing import List

# Define the exact structure we want
class SecurityFinding(BaseModel):
    issue_type: str = Field(description="Short name of the issue")
    category: str = Field(description="Category: Critical Vulnerability, Minor Warning, Dependency Issue, or Security Enhancement")
    confidence_score: int = Field(description="Score from 1-10")
    confidence_reasoning: str = Field(description="Why you assigned this score")
    original_evidence: str = Field(description="The exact text snippet from the input")

class SecurityAnalysis(BaseModel):
    analysis_summary: str = Field(description="Brief overview of what was found")
    findings: List[SecurityFinding]

def get_agent_chains(llm):
    # --- AGENT 1: THE COLLECTOR (Simplified) ---
    # Removed complex examples. Just direct instruction.
    collector_template = """You are a Security Analyst. 
    Analyze the following raw text. 
    Extract ALL sentences that describe security vulnerabilities, weaknesses, or warnings.
    Do not summarize. Extract the exact text.
    If no security issues are found, return "NO_SECURITY_ISSUES".

    RAW TEXT:
    {raw_data}

    RELEVANT EXCERPTS:"""

    collector_prompt = PromptTemplate(
        input_variables=["raw_data"],
        template=collector_template
    )

    # --- AGENT 2: THE NORMALIZER (Structured) ---
    # Using JsonOutputParser to handle the formatting automatically
    parser = JsonOutputParser(pydantic_object=SecurityAnalysis)

    normalizer_template = """You are a Security Data Normalizer.
    Transform the provided security excerpts into a structured JSON format.
    
    {format_instructions}

    INPUT EXCERPTS:
    {collector_output}

    JSON OUTPUT:"""

    normalizer_prompt = PromptTemplate(
        input_variables=["collector_output"],
        template=normalizer_template,
        partial_variables={"format_instructions": parser.get_format_instructions()}
    )
    
    # --- CHAINS ---
    # We use the parser on the normalizer to guarantee JSON
    chains = {
        "collector": collector_prompt | llm,  # Simple text out
        "normalizer": normalizer_prompt | llm | parser # Enforced JSON out
    }

    return chains