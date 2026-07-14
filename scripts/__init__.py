"""
Local-only scripts for CTI platform setup and data ingestion.

These scripts are NOT deployed to AWS Lambda.
They are used for:
- Data ingestion (ingest_to_sqs.py)
- Database initialization (init_cloud_db.py, init_neo4j_schema.py)
- Lambda layer optimization (clean_lambda_layer.py)
- Utility functions for local development
"""
