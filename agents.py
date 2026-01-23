from langchain_core.prompts import PromptTemplate 
from langchain_core.output_parsers import StrOutputParser

def get_agent_chains(llm):

    # AGENT 1: THE COLLECTOR
    # Goal: Extract security signals from noise.
    collector_prompt = PromptTemplate(
        input_variables=["raw_data"],
        template="""Instruct: Extract ONLY security vulnerabilities from the text below. Return a single line summary. If none, say "No security data found."
    Raw Data: {raw_data}
    Output:""" 
    )

    # AGENT 2: THE NORMALIZER
    # Goal: Structure the data and assign confidence.
    normalizer_prompt = PromptTemplate(
        input_variables=["collector_output"],
        template="""Instruct: Convert this finding into JSON format {{ "finding": "...", "confidence": "Low/Med/High" }}. Return ONLY the JSON.
    Input: {collector_output}
    Output:"""
    )

    return {
        "collector": collector_prompt | llm | StrOutputParser(),
        "normalizer": normalizer_prompt | llm | StrOutputParser()
    }
