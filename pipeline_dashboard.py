import sqlite3
import pandas as pd

def generate_retrieval_dashboard(db_path="data/pipeline.sqlite"):
    try:
        conn = sqlite3.connect(db_path)
        
        print("\n" + "="*50)
        print(" 📊 RETRIEVAL LAYER DASHBOARD")
        print("="*50 + "\n")

        # 1. API Fetch Health (From fetch_log)
        print("--- API FETCH HEALTH ---")
        fetch_query = """
            SELECT 
                source, 
                COUNT(*) as total_requests,
                SUM(CASE WHEN http_status = 200 THEN 1 ELSE 0 END) as successful_requests,
                SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) as errors
            FROM fetch_log
            GROUP BY source
        """
        fetch_df = pd.read_sql_query(fetch_query, conn)
        
        if not fetch_df.empty:
            fetch_df['success_rate'] = (fetch_df['successful_requests'] / fetch_df['total_requests'] * 100).round(1).astype(str) + '%'
            print(fetch_df.to_string(index=False))
        else:
            print("No fetch logs found. Run your pipeline first!")

        print("\n--- INGESTION ERRORS ---")
        error_query = "SELECT source, error FROM fetch_log WHERE error IS NOT NULL"
        error_df = pd.read_sql_query(error_query, conn)
        if not error_df.empty:
            print(error_df.to_string(index=False))
        else:
            print("✅ 0 API Errors detected.")

        print("\n" + "-"*50)

        # 2. Data Yield (From normalized_items)
        print("\n--- NORMALIZATION YIELD (SAVED RECORDS) ---")
        yield_query = """
            SELECT 
                package_name,
                source,
                COUNT(*) as total_records_saved
            FROM normalized_items
            GROUP BY package_name, source
            ORDER BY package_name, total_records_saved DESC
        """
        yield_df = pd.read_sql_query(yield_query, conn)
        
        if not yield_df.empty:
            print(yield_df.to_string(index=False))
        else:
            print("No normalized items found.")

        print("\n" + "="*50 + "\n")
        
    except sqlite3.OperationalError:
        print("\n[!] Database not found. Make sure you are running this from the root directory and the pipeline has been run.")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    generate_retrieval_dashboard()
    