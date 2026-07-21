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
                # Count all records from threat_intelligence_records table
                cur.execute("SELECT COUNT(*) FROM threat_intelligence_records")
                # Note: For time-window filtering, add WHERE clause with published_at or last_verified_at
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
            # We measure canonical_id, summary, severity, references_json, and embedding coverage
            query = """
                SELECT
                    source,
                    COUNT(*) as total_records,
                    SUM(CASE WHEN canonical_id IS NOT NULL AND canonical_id != '' THEN 1 ELSE 0 END) as has_id,
                    SUM(CASE WHEN summary IS NOT NULL AND summary != '' THEN 1 ELSE 0 END) as has_summary,
                    SUM(CASE WHEN severity IS NOT NULL AND severity != '' THEN 1 ELSE 0 END) as has_severity,
                    SUM(CASE WHEN references_json IS NOT NULL AND references_json != '[]' THEN 1 ELSE 0 END) as has_refs,
                    SUM(CASE WHEN embedding IS NOT NULL THEN 1 ELSE 0 END) as has_embedding
                FROM threat_intelligence_records
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
                embedding_rate = (row[6] / total) * 100

                # Average completeness across required fields (including embeddings for GraphRAG)
                overall_completeness = (id_rate + summary_rate + severity_rate + refs_rate + embedding_rate) / 5

                print(f"Source: {source.upper()} (Total Records: {total})")
                print(f"  - ID populated: {id_rate:.1f}%")
                print(f"  - Summary populated: {summary_rate:.1f}%")
                print(f"  - Severity populated: {severity_rate:.1f}%")
                print(f"  - References populated: {refs_rate:.1f}%")
                print(f"  - Embeddings populated: {embedding_rate:.1f}%")
                print(f"  >> Overall Schema Completeness: {overall_completeness:.1f}%\n")
    finally:
        conn.close()

def get_verification_metrics():
    """
    Shows summary verification statistics (LLM hallucination detection).
    Useful for Graph-3: Summary Trustworthiness
    """
    print("\n--- 3. Summary Verification Metrics (RQ2: Hallucination Detection) ---")
    conn = get_db_connection()
    if not conn:
        print("Database connection failed.")
        return

    try:
        with conn.cursor() as cur:
            # Get verification statistics
            query = """
                SELECT
                    COUNT(*) as total_verified,
                    SUM(CASE WHEN verdict = 'MATCH' THEN 1 ELSE 0 END) as matches,
                    SUM(CASE WHEN verdict = 'MISMATCH' THEN 1 ELSE 0 END) as mismatches,
                    SUM(CASE WHEN verdict = 'UNVERIFIABLE' THEN 1 ELSE 0 END) as unverifiable,
                    AVG(combined_score) as avg_score,
                    AVG(jaccard_score) as avg_jaccard,
                    AVG(fuzzy_score) as avg_fuzzy
                FROM summary_verification_logs
                WHERE verdict IS NOT NULL;
            """
            cur.execute(query)
            res = cur.fetchone()

            if res and res[0] > 0:
                total = res[0]
                matches = res[1] or 0
                mismatches = res[2] or 0
                unverifiable = res[3] or 0

                print(f"Total Summaries Verified: {total}")
                print(f"  - MATCH (trustworthy): {matches} ({matches/total*100:.1f}%)")
                print(f"  - MISMATCH (hallucination): {mismatches} ({mismatches/total*100:.1f}%)")
                print(f"  - UNVERIFIABLE (scrape failed): {unverifiable} ({unverifiable/total*100:.1f}%)")
                print(f"Average Combined Score: {res[4]:.3f}" if res[4] else "Average Combined Score: N/A")
                print(f"Average Jaccard Score: {res[5]:.3f}" if res[5] else "Average Jaccard Score: N/A")
                print(f"Average Fuzzy Score: {res[6]:.3f}" if res[6] else "Average Fuzzy Score: N/A")

                # Get verification coverage by source
                cur.execute("""
                    SELECT
                        t.source,
                        COUNT(DISTINCT t.id) as total_records,
                        COUNT(DISTINCT v.threat_intel_record_id) as verified_records
                    FROM threat_intelligence_records t
                    LEFT JOIN summary_verification_logs v ON t.id = v.threat_intel_record_id
                    GROUP BY t.source
                    ORDER BY t.source;
                """)
                source_results = cur.fetchall()

                print("\nVerification Coverage by Source:")
                for row in source_results:
                    source = row[0]
                    total_records = row[1]
                    verified_records = row[2] or 0
                    coverage = (verified_records / total_records * 100) if total_records > 0 else 0
                    print(f"  {source.upper()}: {verified_records}/{total_records} ({coverage:.1f}% verified)")

            else:
                print("No verification data found. Run: python -m src.validators.summary_verifier --batch-size 50")
    finally:
        conn.close()


def get_latency_metrics():
    """
    Extracts the LangGraph agent execution speeds logged in the metrics table.
    Useful for Graph-4: Query Performance / Analysis Latency
    """
    print("\n--- 4. System Latency Benchmarks (LangGraph Queries) ---")
    conn = get_db_connection()
    if not conn: return

    try:
        with conn.cursor() as cur:
            # Query average latency metrics from the graph_execution_metrics table
            query = """
                SELECT
                    AVG(retrieval_latency_sec) as avg_retrieval,
                    AVG(analysis_latency_sec) as avg_analysis,
                    AVG(total_latency_sec) as avg_total,
                    COUNT(*) as total_queries,
                    AVG(cves_correlated) as avg_cves,
                    AVG(mitre_capec_linked) as avg_mitre,
                    SUM(CASE WHEN guardrail_triggered = TRUE THEN 1 ELSE 0 END) as guardrail_triggers
                FROM graph_execution_metrics
                WHERE total_latency_sec > 0;
            """
            cur.execute(query)
            res = cur.fetchone()
            if res and res[0] is not None:
                print(f"Total Queries Executed: {res[3]}")
                print(f"Average Retrieval Time (Researcher Node): {res[0]:.3f} seconds")
                print(f"Average Analysis Time (Analyzer Node): {res[1]:.3f} seconds")
                print(f"Average Total Query Execution Time: {res[2]:.3f} seconds")
                print(f"Average CVEs per Query: {res[4]:.1f}")
                print(f"Average MITRE/CAPEC Links per Query: {res[5]:.1f}")
                print(f"Guardrail Triggers: {res[6]} ({res[6]/res[3]*100:.1f}%)" if res[3] > 0 else "Guardrail Triggers: 0")
            else:
                print("No latency data found. Run queries via graph_agents.py or the dashboard first.")
    finally:
        conn.close()

if __name__ == "__main__":
    get_ingestion_success_rate()
    get_schema_completeness()
    get_verification_metrics()
    get_latency_metrics()