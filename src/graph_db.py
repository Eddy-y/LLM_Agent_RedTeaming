"""
Neo4j Aura connection and graph database operations.

This module provides connection pooling, session management, and batch insertion
for the Neo4j knowledge graph. Compatible with Neo4j Aura Free (no APOC required).
"""

import logging
import ssl
import os
import sys
from contextlib import contextmanager
from typing import Dict, List, Any

from neo4j import GraphDatabase, Session
from neo4j.exceptions import ServiceUnavailable, TransientError

try:
    from config import get_settings
except ImportError:
    from src.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Global driver instance for connection pooling
_neo4j_driver = None


def _configure_ssl_for_platform():
    """
    Configure SSL certificates based on the platform.

    Windows: Use certifi bundle (Python often doesn't have system certs)
    Linux/Lambda: Use system certificates (already properly configured)
    """
    if sys.platform == "win32":
        try:
            import certifi
            import certifi_win32  # Patches certifi to use Windows cert store
            cert_path = certifi.where()

            # Set environment variables for SSL certificate verification
            os.environ["SSL_CERT_FILE"] = cert_path
            os.environ["REQUESTS_CA_BUNDLE"] = cert_path

            logger.info(f"Windows: Using certifi bundle at {cert_path}")
        except ImportError:
            logger.warning("certifi not installed - SSL verification may fail on Windows")
    else:
        # Linux/Lambda: System certificates are already configured
        logger.debug("Linux: Using system certificate store")


def get_neo4j_driver():
    """
    Get or create Neo4j driver with connection pooling.

    Driver is cached globally and reused across Lambda invocations
    for optimal performance.

    Returns:
        Neo4j driver instance
    """
    global _neo4j_driver

    if _neo4j_driver is None:
        if not settings.neo4j_password:
            raise ValueError("NEO4J_PASSWORD environment variable not set")

        # Configure SSL certificates based on platform (Windows vs Linux/Lambda)
        _configure_ssl_for_platform()

        logger.info(f"Initializing Neo4j driver: {settings.neo4j_uri}")

        # neo4j+s:// URI scheme handles encryption automatically
        # SSL_CERT_FILE environment variable is used by the driver
        _neo4j_driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_lifetime=3600,  # 1 hour
            max_connection_pool_size=50,
            connection_acquisition_timeout=120  # 2 minutes
        )

        # Verify connectivity
        try:
            _neo4j_driver.verify_connectivity()
            logger.info("✅ Successfully connected to Neo4j Aura")
        except ServiceUnavailable as e:
            logger.error(f"❌ Failed to connect to Neo4j: {e}")
            _neo4j_driver = None
            raise

    return _neo4j_driver


@contextmanager
def get_neo4j_session(database: str = None):
    """
    Context manager for Neo4j sessions with automatic cleanup.

    Args:
        database: Database name (defaults to NEO4J_DATABASE from config)

    Yields:
        Neo4j session

    Example:
        with get_neo4j_session() as session:
            result = session.run("MATCH (n) RETURN count(n)")
    """
    driver = get_neo4j_driver()
    db_name = database or settings.neo4j_database
    session = driver.session(database=db_name)

    try:
        yield session
    finally:
        session.close()


def close_neo4j_driver():
    """
    Close driver connection pool.

    Call this during graceful shutdown to release resources.
    """
    global _neo4j_driver

    if _neo4j_driver:
        logger.info("Closing Neo4j driver")
        _neo4j_driver.close()
        _neo4j_driver = None


def get_id_field(node_type: str) -> str:
    """
    Get primary key field name for each node type.

    Args:
        node_type: Neo4j node label (e.g., "Vulnerability", "Package")

    Returns:
        Primary key field name
    """
    mapping = {
        "Vulnerability": "canonical_id",
        "Package": "name",
        "Weakness": "cwe_id",
        "AttackTactic": "mitre_id",
        "AttackPattern": "capec_id",
        "DefenseControl": "control_id"
    }
    return mapping.get(node_type, "id")


def insert_graph_batch(session: Session, graph_data: Dict[str, List[Dict[str, Any]]]):
    """
    Transactional batch insert of nodes and relationships using MERGE.

    Uses native Cypher compatible with Neo4j Aura Free (no APOC plugin required).
    MERGE ensures idempotency - duplicate inserts update existing nodes/relationships.

    Args:
        session: Active Neo4j session
        graph_data: Dictionary with "nodes" and "relationships" keys
            nodes: [{"type": "Vulnerability", "properties": {...}}, ...]
            relationships: [{"type": "AFFECTS", "from_node": {...}, "to_node": {...}, "properties": {...}}, ...]

    Returns:
        Dictionary with counts of created nodes and relationships

    Raises:
        TransientError: On temporary network/database issues (caller should retry)
        ServiceUnavailable: On connection failures
    """
    nodes_created = 0
    rels_created = 0

    try:
        # Insert nodes first (grouped by type for efficient MERGE)
        if graph_data.get("nodes"):
            # Group nodes by type to batch by label
            nodes_by_type = {}
            for node in graph_data["nodes"]:
                node_type = node["type"]
                if node_type not in nodes_by_type:
                    nodes_by_type[node_type] = []
                nodes_by_type[node_type].append(node["properties"])

            # Insert each type separately with appropriate ID field
            for node_type, nodes in nodes_by_type.items():
                id_field = get_id_field(node_type)

                # Dynamic Cypher query with literal node label (safe - from our mapping)
                node_query = f"""
                UNWIND $nodes AS node
                MERGE (n:{node_type} {{{id_field}: node.{id_field}}})
                SET n += node
                RETURN count(n) AS count
                """

                result = session.run(node_query, nodes=nodes)
                record = result.single()
                if record:
                    nodes_created += record["count"]
                    logger.debug(f"Created/updated {record['count']} {node_type} nodes")

        # Insert relationships (must be done after nodes exist)
        if graph_data.get("relationships"):
            for rel in graph_data["relationships"]:
                try:
                    # Build dynamic MERGE query based on relationship type
                    # Safe - relationship types validated in graph_extractor.py
                    rel_query = f"""
                    MATCH (from:{rel['from_node']['type']} {{{rel['from_node']['id_field']}: $from_id}})
                    MATCH (to:{rel['to_node']['type']} {{{rel['to_node']['id_field']}: $to_id}})
                    MERGE (from)-[r:{rel['type']}]->(to)
                    SET r += $properties
                    RETURN r
                    """

                    result = session.run(
                        rel_query,
                        from_id=rel['from_node']['id_value'],
                        to_id=rel['to_node']['id_value'],
                        properties=rel.get('properties', {})
                    )

                    if result.single():
                        rels_created += 1

                except Exception as e:
                    # Log relationship errors but don't fail entire batch
                    logger.warning(
                        f"Failed to create relationship {rel['from_node']['id_value']} "
                        f"-[{rel['type']}]-> {rel['to_node']['id_value']}: {e}"
                    )
                    continue

        logger.info(f"Graph batch insert: {nodes_created} nodes, {rels_created} relationships")

        return {
            "nodes_created": nodes_created,
            "relationships_created": rels_created
        }

    except TransientError as e:
        logger.warning(f"Transient Neo4j error (retry recommended): {e}")
        raise
    except Exception as e:
        logger.error(f"Graph batch insert failed: {e}")
        raise


def test_connection() -> bool:
    """
    Test Neo4j connection and return success status.

    Returns:
        True if connection successful, False otherwise
    """
    try:
        with get_neo4j_session() as session:
            result = session.run("RETURN 1 AS test")
            record = result.single()
            if record and record["test"] == 1:
                logger.info("✅ Neo4j connection test passed")
                return True
        return False
    except Exception as e:
        logger.error(f"❌ Neo4j connection test failed: {e}")
        return False
