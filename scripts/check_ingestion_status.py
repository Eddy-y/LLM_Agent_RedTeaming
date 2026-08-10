"""
check_ingestion_status.py

Diagnostic script to verify ingestion pipeline health.
Checks SQS queue status, database records, and Lambda configuration.
"""

import sys
sys.path.insert(0, '.')

import boto3
import os
from dotenv import load_dotenv
from src.db import get_db_connection, release_db_connection

load_dotenv()

def check_sqs_queue():
    """Check SQS queue for pending messages."""
    print("\n" + "=" * 70)
    print("SQS QUEUE STATUS")
    print("=" * 70)

    sqs_client = boto3.client('sqs', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    queue_url = os.environ.get('SQS_QUEUE_URL')

    if not queue_url:
        print("  [ERROR] SQS_QUEUE_URL not found in environment")
        return

    try:
        response = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                'ApproximateNumberOfMessages',
                'ApproximateNumberOfMessagesNotVisible',
                'ApproximateNumberOfMessagesDelayed'
            ]
        )

        attrs = response['Attributes']
        available = int(attrs.get('ApproximateNumberOfMessages', 0))
        in_flight = int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0))
        delayed = int(attrs.get('ApproximateNumberOfMessagesDelayed', 0))

        print(f"\nQueue URL: {queue_url}")
        print(f"\nMessages available:    {available:>6} (waiting to be processed)")
        print(f"Messages in-flight:    {in_flight:>6} (being processed now)")
        print(f"Messages delayed:      {delayed:>6} (scheduled for later)")
        print(f"Total pending:         {available + in_flight + delayed:>6}")

        if available > 0:
            print("\n[ISSUE] Messages are queued but not being processed!")
            print("Possible causes:")
            print("  1. Lambda worker not deployed or not running")
            print("  2. Lambda trigger not configured for this queue")
            print("  3. Lambda execution role lacks SQS permissions")
            print("\nRecommended actions:")
            print("  - Run local worker: python test/run_worker.py")
            print("  - Check Lambda logs: aws logs tail /aws/lambda/RedteamWorker --follow")
            print("  - Verify deployment: sam deploy --profile eddy_tamusa_dev")
        elif in_flight > 0:
            print("\n[INFO] Messages are currently being processed by Lambda")
            print("Wait 1-2 minutes and check database again")
        else:
            print("\n[OK] No pending messages in queue")

    except Exception as e:
        print(f"  [ERROR] Could not check queue: {e}")

def check_database_records():
    """Check recent database records."""
    print("\n" + "=" * 70)
    print("DATABASE RECORDS")
    print("=" * 70)

    conn = get_db_connection()
    if not conn:
        print("  [ERROR] Could not connect to database")
        return

    try:
        with conn.cursor() as cur:
            # Total records by source
            cur.execute("""
                SELECT source, COUNT(*) as count
                FROM threat_intelligence_records
                GROUP BY source
                ORDER BY source
            """)
            counts = cur.fetchall()

            if counts:
                print("\nRecords by source:")
                total = 0
                for source, count in counts:
                    print(f"  {source:20} | {count:>6} records")
                    total += count
                print(f"  {'TOTAL':20} | {total:>6} records")
            else:
                print("\n[WARNING] No records found in database")
                print("Either:")
                print("  1. Fresh database (never ingested)")
                print("  2. All messages failed processing")
                print("  3. Worker hasn't run yet")

            # Recent records (last 10)
            cur.execute("""
                SELECT id, source, canonical_id, title,
                       TO_CHAR(published_at, 'YYYY-MM-DD HH24:MI') as published
                FROM threat_intelligence_records
                ORDER BY id DESC
                LIMIT 10
            """)
            recent = cur.fetchall()

            if recent:
                print("\nMost recent records:")
                print(f"  {'ID':>6} | {'Source':20} | {'Canonical ID':20} | {'Published':16}")
                print("  " + "-" * 70)
                for row in recent:
                    rec_id, source, canonical_id, title, published = row
                    canonical_id = canonical_id or "N/A"
                    print(f"  {rec_id:>6} | {source:20} | {canonical_id:20} | {published or 'N/A':16}")

            # Embedding coverage
            cur.execute("""
                SELECT
                    COUNT(*) as total,
                    COUNT(embedding) as with_embedding,
                    ROUND(COUNT(embedding)::numeric / COUNT(*)::numeric * 100, 1) as coverage_pct
                FROM threat_intelligence_records
            """)
            emb_stats = cur.fetchone()

            if emb_stats and emb_stats[0] > 0:
                total, with_emb, coverage = emb_stats
                print(f"\nEmbedding coverage: {with_emb}/{total} ({coverage}%)")
                if coverage < 100:
                    print("  [INFO] Some records missing embeddings (Lambda may still be processing)")

    except Exception as e:
        print(f"  [ERROR] Database query failed: {e}")
    finally:
        release_db_connection(conn)

def check_pagination_state():
    """Check pagination offsets."""
    print("\n" + "=" * 70)
    print("PAGINATION STATE")
    print("=" * 70)

    conn = get_db_connection()
    if not conn:
        return

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT source, package_name, offset_value
                FROM pipeline_state
                ORDER BY source, package_name
            """)
            state = cur.fetchall()

            if state:
                print(f"\n  {'Source':20} | {'Package':15} | {'Offset':>6}")
                print("  " + "-" * 50)
                for source, package, offset in state:
                    print(f"  {source:20} | {package:15} | {offset:>6}")
            else:
                print("\n  [INFO] No pagination state found (first run)")

    except Exception as e:
        print(f"  [ERROR] Could not fetch pagination state: {e}")
    finally:
        release_db_connection(conn)

def check_lambda_config():
    """Check Lambda configuration."""
    print("\n" + "=" * 70)
    print("LAMBDA CONFIGURATION")
    print("=" * 70)

    try:
        lambda_client = boto3.client('lambda', region_name=os.environ.get('AWS_REGION', 'us-east-1'))

        # Try to get Lambda function (from template.yaml, function name is RedteamWorker)
        function_name = 'RedteamWorker'

        try:
            response = lambda_client.get_function(FunctionName=function_name)
            print(f"\nLambda Function: {function_name}")
            print(f"Status: {response['Configuration']['State']}")
            print(f"Last Modified: {response['Configuration']['LastModified']}")
            print(f"Memory: {response['Configuration']['MemorySize']} MB")
            print(f"Timeout: {response['Configuration']['Timeout']} seconds")

            # Check event source mappings (SQS trigger)
            mappings = lambda_client.list_event_source_mappings(FunctionName=function_name)

            if mappings['EventSourceMappings']:
                print("\nSQS Event Source Mappings:")
                for mapping in mappings['EventSourceMappings']:
                    print(f"  State: {mapping['State']}")
                    print(f"  Batch Size: {mapping['BatchSize']}")
                    print(f"  Queue ARN: {mapping['EventSourceArn']}")

                    if mapping['State'] != 'Enabled':
                        print(f"  [WARNING] Event source mapping is {mapping['State']}, not Enabled!")
            else:
                print("\n[WARNING] No SQS triggers configured for Lambda!")
                print("This means Lambda won't automatically process queued messages.")
                print("\nFix: Ensure template.yaml has SQS event source, then redeploy:")
                print("  sam build && sam deploy --profile eddy_tamusa_dev")

        except lambda_client.exceptions.ResourceNotFoundException:
            print(f"\n[ERROR] Lambda function '{function_name}' not found!")
            print("Lambda is not deployed. Deploy with:")
            print("  sam build && sam deploy --profile eddy_tamusa_dev")

    except Exception as e:
        print(f"\n[ERROR] Could not check Lambda: {e}")
        print("Possible causes:")
        print("  1. AWS credentials not configured")
        print("  2. Wrong AWS profile")
        print("  3. Lambda not deployed yet")

def main():
    print("\n" + "=" * 70)
    print("INGESTION PIPELINE DIAGNOSTIC")
    print("=" * 70)

    check_sqs_queue()
    check_database_records()
    check_pagination_state()
    check_lambda_config()

    print("\n" + "=" * 70)
    print("TROUBLESHOOTING RECOMMENDATIONS")
    print("=" * 70)
    print("""
If messages are queued but not processed:

1. RUN LOCAL WORKER (fastest way to see errors):
   python test/run_worker.py

   This will process queued messages locally and show detailed error logs.

2. CHECK LAMBDA LOGS (if deployed):
   aws logs tail /aws/lambda/RedteamWorker --follow --profile eddy_tamusa_dev

3. VERIFY DEPLOYMENT:
   sam build
   sam deploy --profile eddy_tamusa_dev

4. CHECK AWS CREDENTIALS:
   aws sts get-caller-identity --profile eddy_tamusa_dev

5. PURGE QUEUE (if messages are stuck/corrupted):
   aws sqs purge-queue --queue-url $SQS_QUEUE_URL --profile eddy_tamusa_dev

   WARNING: This deletes all queued messages!
""")

if __name__ == "__main__":
    main()
