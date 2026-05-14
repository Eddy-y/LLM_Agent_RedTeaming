import json
import boto3
import os
from src.agents import (
    run_pypi_agent, run_github_agent, run_nvd_agent, 
    run_mitre_agent, run_capec_agent, run_central_normalizer
)
from src.db import insert_normalized_batch # This will be updated to point to Amazon RDS later

def lambda_handler(event, context):
    """
    This function is triggered automatically by AWS whenever a new message enters the SQS queue.
    """
    for record in event['Records']:
        payload = json.loads(record['body'])
        
        source = payload['source']
        raw_data = payload['raw_payload']
        package = payload['package_target']
        run_id = payload['run_id']
        
        specialist_output = None
        
        # 1. Route the raw payload to the correct Bedrock Specialist Agent
        if source == "nvd":
            specialist_output = run_nvd_agent([raw_data], package)
        elif source == "pypi":
            specialist_output = run_pypi_agent([raw_data])
        # ... (Add routing for github, mitre, capec) ...
        
        # 2. Pass the extracted facts to the Central Normalizer
        if specialist_output:
            normalized_data = run_central_normalizer(specialist_output, source)
            
            # 3. Write the final result to the cloud database
            if normalized_data:
                for item in normalized_data:
                    item["source"] = source
                
                # In the final phase, conn will point to Amazon RDS (PostgreSQL)
                # insert_normalized_batch(rds_conn, run_id, package, normalized_data)
                print(f"Successfully processed and normalized: {normalized_data[0].get('canonical_id')}")

    return {
        'statusCode': 200,
        'body': json.dumps('Successfully processed SQS records.')
    }