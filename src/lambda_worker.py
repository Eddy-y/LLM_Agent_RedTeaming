import json
import boto3
from src.agents import (
    run_pypi_agent, run_github_agent, run_nvd_agent, 
    run_mitre_agent, run_capec_agent, run_central_normalizer
)
from src.db import get_db_connection, insert_normalized_batch

def lambda_handler(event, context):
    """
    Triggered automatically by AWS SQS. Processes raw threat intelligence
    through Bedrock and saves the normalized result to PostgreSQL.
    """
    
    # 1. Open the connection to the Amazon RDS Database
    rds_conn = get_db_connection()
    if not rds_conn:
        return {
            'statusCode': 500,
            'body': json.dumps('Database connection failed.')
        }

    try:
        for record in event['Records']:
            payload = json.loads(record['body'])
            
            source = payload['source']
            raw_data = payload['raw_payload']
            package = payload['package_target']
            run_id = payload['run_id']
            
            specialist_output = None
            
            # 2. Route the raw payload to the correct Bedrock Specialist
            if source == "nvd":
                specialist_output = run_nvd_agent([raw_data], package)
            elif source == "pypi":
                specialist_output = run_pypi_agent([raw_data])
            # (Add routing for github, mitre, and capec here as needed)
            
            # 3. Pass the extracted facts to the Central Normalizer
            if specialist_output:
                normalized_data = run_central_normalizer(specialist_output, source)
                
                # 4. Write the final result to the cloud database
                if normalized_data:
                    for item in normalized_data:
                        item["source"] = source
                    
                    # Call the function with the active connection
                    insert_normalized_batch(rds_conn, run_id, package, normalized_data)
                    print(f"Successfully processed: {normalized_data[0].get('canonical_id')}")

    except Exception as e:
        print(f"[!] Lambda Execution Error: {e}")
        # Raising the error forces the message back into the SQS queue (or DLQ)
        raise e
        
    finally:
        # 5. CRITICAL: Always close the connection to prevent RDS limits
        rds_conn.close()

    return {
        'statusCode': 200,
        'body': json.dumps('Successfully processed SQS records.')
    }