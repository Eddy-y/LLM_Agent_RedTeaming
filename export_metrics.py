# export_metrics.py
import pandas as pd
from src.db import get_db_connection

def export_to_csv():
    conn = get_db_connection()
    if not conn:
        print("[!] Connection failed.")
        return

    try:
        print("[*] Fetching graph execution metrics from AWS RDS...")
        # Query all records from graph_execution_metrics table
        df = pd.read_sql_query("SELECT * FROM graph_execution_metrics ORDER BY evaluated_at DESC;", conn)

        if df.empty:
            print("[-] No records found to export.")
            return

        # Export cleanly to CSV
        output_filename = "graph_execution_metrics.csv"
        df.to_csv(output_filename, index=False)
        print(f"[+] Success! Exported {len(df)} graph execution records to '{output_filename}'")
        
    except Exception as e:
        print(f"[!] Export Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    export_to_csv()