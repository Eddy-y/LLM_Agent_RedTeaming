# export_metrics.py
import pandas as pd
from src.db import get_db_connection

def export_to_csv():
    conn = get_db_connection()
    if not conn:
        print("[!] Connection failed.")
        return
        
    try:
        print("[*] Fetching evaluation metrics from AWS RDS...")
        # Query all records
        df = pd.read_sql_query("SELECT * FROM evaluation_metrics ORDER BY evaluated_at DESC;", conn)
        
        if df.empty:
            print("[-] No records found to export.")
            return
            
        # Export cleanly to CSV
        output_filename = "evaluation_metrics2.csv"
        df.to_csv(output_filename, index=False)
        print(f"[+] Success! Exported {len(df)} evaluation records to '{output_filename}'")
        
    except Exception as e:
        print(f"[!] Export Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    export_to_csv()