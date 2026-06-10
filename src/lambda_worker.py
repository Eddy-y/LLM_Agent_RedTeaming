import json
from src.agents import (
    run_pypi_agent, run_github_agent, run_nvd_agent, 
    run_mitre_agent, run_capec_agent, run_central_normalizer
)
from src.db import get_db_connection, release_db_connection, insert_normalized_batch

def lambda_handler(event, context):
    rds_conn = get_db_connection()
    if not rds_conn:
        raise Exception('Database connection failed.')

    try:
        for record in event['Records']:
            if not record.get('body'): continue
            payload = json.loads(record['body'])
            source = payload.get('source')
            raw_data = payload.get('raw_payload')
            package = payload.get('package_target')
            run_id = payload.get('run_id')
            
            if not raw_data: continue

            specialist_output = None
            
            if source == "nvd": specialist_output = run_nvd_agent([raw_data], package)
            elif source == "pypi": specialist_output = run_pypi_agent([raw_data])
            elif source == "github_advisories" or source == "github": specialist_output = run_github_agent([raw_data])
            elif source == "attack": specialist_output = run_mitre_agent([raw_data])
            elif source == "capec": specialist_output = run_capec_agent([raw_data])
            else:
                print(f"[!] Unknown source received from SQS: {source}")
                continue
            
            if specialist_output:
                normalized_data = run_central_normalizer(specialist_output, source)
                if normalized_data:
                    for item in normalized_data:
                        item["source"] = source
                    insert_normalized_batch(rds_conn, run_id, package, normalized_data)

    except Exception as e:
        print(f"[!] Lambda Execution Error: {e}")
        raise e
    finally:
        release_db_connection(rds_conn)

    return {'statusCode': 200, 'body': 'Processed'}