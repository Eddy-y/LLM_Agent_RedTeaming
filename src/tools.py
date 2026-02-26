import sqlite3
from langchain_core.tools import tool
from .config import get_settings

@tool
def search_local_cti(package_name: str) -> str:
    """
    Searches the local normalized SQLite database for Threat Intelligence 
    related to a specific software package.
    
    Args:
        package_name: The name of the software package (e.g., 'flask', 'django').
    """
    settings = get_settings()
    db_path = settings.db_path
    
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Query the normalized table for anything related to the package
        # We also use LIKE in case the package name is mentioned in CAPEC/MITRE summaries
        cursor.execute(
            """
            SELECT source, record_type, canonical_id, title, summary, severity 
            FROM normalized_items 
            WHERE package_name = ? OR summary LIKE ? OR title LIKE ?
            LIMIT 50
            """, 
            (package_name, f"%{package_name}%", f"%{package_name}%")
        )
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return f"No local threat intelligence found for package: {package_name}."
            
        # Format the SQL rows into a readable string for the LLM
        formatted_results = f"--- CTI Database Results for '{package_name}' ---\n"
        for row in rows:
            formatted_results += (
                f"\nSource: {row['source'].upper()} | Type: {row['record_type']}\n"
                f"ID: {row['canonical_id']} | Severity: {row['severity']}\n"
                f"Title: {row['title']}\n"
                f"Summary: {row['summary']}\n"
                f"-" * 40
            )
            
        return formatted_results
        
    except Exception as e:
        return f"Error accessing local CTI database: {str(e)}"

# Update the exported tools list for LangGraph to use
search_tools = [search_local_cti]
