"""
tools.py
LangGraph tools for the Augmentation Agent.
Migrated to query the Amazon RDS PostgreSQL database.
"""

from langchain_core.tools import tool
import psycopg2.extras
from db import get_db_connection

@tool
def search_local_cti(package_name: str) -> str:
    """
    Searches the cloud PostgreSQL database for Threat Intelligence 
    related to a specific software package.
    
    Args:
        package_name: The name of the software package (e.g., 'flask', 'django').
    """
    conn = get_db_connection()
    if not conn:
        return "Error: Could not connect to the cloud database."
        
    try:
        # Use RealDictCursor to access columns by name easily
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # PostgreSQL uses %s for parameter binding and ILIKE for case-insensitive matching
        cursor.execute(
            """
            SELECT source, record_type, canonical_id, title, summary, severity 
            FROM normalized_items 
            WHERE package_name = %s OR summary ILIKE %s OR title ILIKE %s
            LIMIT 50
            """, 
            (package_name, f"%{package_name}%", f"%{package_name}%")
        )
        
        rows = cursor.fetchall()
        
        if not rows:
            return f"No threat intelligence found in the database for package: {package_name}."
            
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
        return f"Error accessing cloud CTI database: {str(e)}"
    finally:
        if conn:
            conn.close()