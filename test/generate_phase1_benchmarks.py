import os
import boto3
from datetime import datetime, timedelta
from src.db import get_db_connection

# Initialize AWS CloudWatch client for queue metrics
cw_client = boto3.client('cloudwatch', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
queue_name = os.environ.get('SQS_QUEUE_URL', '').split('/')[-1]

def get_ingestion_success_rate(hours_back=24):
    """
    Compares messages sent to SQS vs. records successfully saved in RDS.
    Useful for Graph-1: Ingestion Success Rate
    """
    print(f"\n--- 1. Ingestion Success Rate (Last {hours_back} hours) ---")
    
    # 1. Get total SQS messages sent via CloudWatch
    start_time = datetime.utcnow() - timedelta(hours=hours_back)
    response = cw_client.get_metric_statistics(
        Namespace='AWS/SQS',
        MetricName='NumberOfMessagesSent',
        Dimensions=[{'Name': 'QueueName', 'Value': queue_name}],
        StartTime=start_time,
        EndTime=datetime.utcnow(),
        Period=3600 * hours_back,
        Statistics=['Sum']
    )
    
    sqs_sent = 0
    if response['Datapoints']:
        sqs_sent = int(response['Datapoints'][0]['Sum'])

    # 2. Get total records inserted into the database
    conn = get_db_connection()
    db_saved = 0
    if conn:
        try:
            with conn.cursor() as cur:
                # Assuming run_id contains a timestamp or items were recently added
                cur.execute("SELECT COUNT(*) FROM normalized_items") 
                # Note: For production, add a 'created_at' timestamp to normalized_items to filter by the same time window
                db_saved = cur.fetchone()[0]
        finally:
            conn.close()

    success_rate = (db_saved / sqs_sent * 100) if sqs_sent > 0 else 0
    print(f"Total Raw Items Pushed to Queue: {sqs_sent}")
    print(f"Total Clean Items Saved to DB: {db_saved}")
    print(f"Ingestion Success Rate: {success_rate:.2f}%")

def get_schema_completeness():
    """
    Calculates the % of populated fields per source.
    Useful for Graph-1: Schema Completeness
    """
    print("\n--- 2. Schema Completeness by Source ---")
    conn = get_db_connection()
    if not conn:
        print("Database connection failed.")
        return

    try:
        with conn.cursor() as cur:
            # We measure canonical_id, summary, severity, and references_json
            query = """
                SELECT 
                    source,
                    COUNT(*) as total_records,
                    SUM(CASE WHEN canonical_id IS NOT NULL AND canonical_id != '' THEN 1 ELSE 0 END) as has_id,
                    SUM(CASE WHEN summary IS NOT NULL AND summary != '' THEN 1 ELSE 0 END) as has_summary,
                    SUM(CASE WHEN severity IS NOT NULL AND severity != '' THEN 1 ELSE 0 END) as has_severity,
                    SUM(CASE WHEN references_json IS NOT NULL AND references_json != '[]' THEN 1 ELSE 0 END) as has_refs
                FROM normalized_items
                GROUP BY source;
            """
            cur.execute(query)
            results = cur.fetchall()
            
            for row in results:
                source = row[0]
                total = row[1]
                id_rate = (row[2] / total) * 100
                summary_rate = (row[3] / total) * 100
                severity_rate = (row[4] / total) * 100
                refs_rate = (row[5] / total) * 100
                
                # Average completeness across required fields
                overall_completeness = (id_rate + summary_rate + severity_rate + refs_rate) / 4
                
                print(f"Source: {source.upper()} (Total Records: {total})")
                print(f"  - ID populated: {id_rate:.1f}%")
                print(f"  - Summary populated: {summary_rate:.1f}%")
                print(f"  - Severity populated: {severity_rate:.1f}%")
                print(f"  - References populated: {refs_rate:.1f}%")
                print(f"  >> Overall Schema Completeness: {overall_completeness:.1f}%\n")
    finally:
        conn.close()

def get_latency_metrics():
    """
    Extracts the agent evaluation speeds logged in the metrics table.
    Useful for Graph-4: Update / Analysis Latency
    """
    print("--- 3. System Latency Benchmarks ---")
    conn = get_db_connection()
    if not conn: return

    try:
        with conn.cursor() as cur:
            # Query average latency metrics from the evaluation_metrics table
            query = """
                SELECT 
                    AVG(retrieval_latency_sec) as avg_retrieval,
                    AVG(analysis_latency_sec) as avg_analysis,
                    AVG(total_latency_sec) as avg_total
                FROM evaluation_metrics
                WHERE total_latency_sec > 0;
            """
            cur.execute(query)
            res = cur.fetchone()
            if res and res[0] is not None:
                print(f"Average Retrieval Time (Researcher Node): {res[0]:.3f} seconds")
                print(f"Average Analysis Time (Analyzer Node): {res[1]:.3f} seconds")
                print(f"Average Total Agent Execution Time: {res[2]:.3f} seconds")
            else:
                print("No latency data found. Run a few dashboard queries first.")
    finally:
        conn.close()

if __name__ == "__main__":
    get_ingestion_success_rate()
    get_schema_completeness()
    get_latency_metrics()