import json
import logging
from agents import (
    run_pypi_agent, run_github_agent, run_nvd_agent,
    run_mitre_agent, run_capec_agent, run_central_normalizer
)
from db import get_db_connection, release_db_connection, insert_normalized_batch

# Support both Lambda (flat) and local (src/) import paths
try:
    # Lambda environment (no src. prefix)
    from graph_extractor import extract_graph_entities
    from graph_db import get_neo4j_session, insert_graph_batch
    from embeddings import generate_embedding
except ImportError:
    # Local environment (with src. prefix)
    from src.graph_extractor import extract_graph_entities
    from src.graph_db import get_neo4j_session, insert_graph_batch
    from src.embeddings import generate_embedding

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
                # Extract specialist relationships (if present in output)
                raw_relationships = []
                for output in specialist_output:
                    if isinstance(output, dict) and "relationships" in output:
                        raw_relationships.extend(output.get("relationships", []))

                # DEBUG: Log relationship extraction
                logger.info(f"[GRAPH DEBUG] Source: {source}, Specialist outputs: {len(specialist_output)}, Relationships extracted: {len(raw_relationships)}")
                if raw_relationships:
                    logger.info(f"[GRAPH DEBUG] Sample relationships: {raw_relationships[:3]}")
                else:
                    logger.warning(f"[GRAPH DEBUG] No relationships found in specialist output from {source}")

                # Normalize data (existing functionality)
                normalized_data = run_central_normalizer(specialist_output, source)

                if normalized_data:
                    # Generate embeddings for semantic search
                    for item in normalized_data:
                        item["source"] = source
                        summary = item.get("summary", "")
                        if summary:
                            try:
                                embedding = generate_embedding(summary)
                                if embedding:
                                    item["embedding"] = embedding
                            except Exception as e:
                                logger.warning(f"Failed to generate embedding for {item.get('canonical_id')}: {e}")
                                # Continue without embedding - not critical

                    # Prepare graph data from normalized records and relationships
                    graph_data = extract_graph_entities(normalized_data, raw_relationships)

                    # Dual write: PostgreSQL + Neo4j
                    try:
                        # 1. Write to PostgreSQL with embeddings
                        insert_normalized_batch(rds_conn, run_id, package, normalized_data)

                        # 2. Write to Neo4j graph
                        try:
                            with get_neo4j_session() as neo4j_session:
                                result = neo4j_session.execute_write(insert_graph_batch, graph_data)
                                logger.info(
                                    f"Dual write complete: {len(normalized_data)} records to RDS, "
                                    f"{result['nodes_created']} nodes + {result['relationships_created']} edges to Neo4j"
                                )
                        except Exception as neo4j_error:
                            # Log Neo4j errors but don't fail the entire batch
                            # PostgreSQL is the source of truth
                            logger.error(f"Neo4j write failed (PostgreSQL write succeeded): {neo4j_error}")

                    except Exception as db_error:
                        logger.error(f"Database write failed: {db_error}")
                        raise

    except Exception as e:
        print(f"[!] Lambda Execution Error: {e}")
        raise e
    finally:
        release_db_connection(rds_conn)

    return {'statusCode': 200, 'body': 'Processed'}