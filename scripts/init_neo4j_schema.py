"""
Initialize Neo4j graph schema with constraints and indexes.

Run this script once after creating your Neo4j Aura instance to set up
the knowledge graph schema: uniqueness constraints, indexes, and full-text search.
"""

import logging
import sys
from neo4j.exceptions import ClientError

from src.graph_db import get_neo4j_session, test_connection

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def create_constraints():
    """
    Create uniqueness constraints on primary keys.

    Constraints automatically create indexes and enforce data integrity.
    """
    constraints = [
        # Vulnerability nodes (CVE, GHSA)
        ("CREATE CONSTRAINT vuln_canonical_id IF NOT EXISTS "
         "FOR (v:Vulnerability) REQUIRE v.canonical_id IS UNIQUE"),

        # Package nodes
        ("CREATE CONSTRAINT package_name IF NOT EXISTS "
         "FOR (p:Package) REQUIRE p.name IS UNIQUE"),

        # Weakness nodes (CWE)
        ("CREATE CONSTRAINT weakness_cwe_id IF NOT EXISTS "
         "FOR (w:Weakness) REQUIRE w.cwe_id IS UNIQUE"),

        # AttackTactic nodes (MITRE ATT&CK)
        ("CREATE CONSTRAINT tactic_mitre_id IF NOT EXISTS "
         "FOR (t:AttackTactic) REQUIRE t.mitre_id IS UNIQUE"),

        # AttackPattern nodes (CAPEC)
        ("CREATE CONSTRAINT pattern_capec_id IF NOT EXISTS "
         "FOR (p:AttackPattern) REQUIRE p.capec_id IS UNIQUE"),

        # DefenseControl nodes
        ("CREATE CONSTRAINT control_id IF NOT EXISTS "
         "FOR (d:DefenseControl) REQUIRE d.control_id IS UNIQUE"),
    ]

    with get_neo4j_session() as session:
        for constraint_query in constraints:
            try:
                session.run(constraint_query)
                logger.info(f"✅ Created constraint: {constraint_query.split()[2]}")
            except ClientError as e:
                if "EquivalentSchemaRuleAlreadyExists" in str(e):
                    logger.info(f"⏭️  Constraint already exists: {constraint_query.split()[2]}")
                else:
                    logger.error(f"❌ Failed to create constraint: {e}")
                    raise


def create_indexes():
    """
    Create indexes for frequently queried properties.

    Note: Aura Free does not support composite indexes, so we create single-property indexes.
    """
    indexes = [
        # Severity filtering (frequently used in queries)
        "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",

        # Published date filtering (time-series queries)
        "CREATE INDEX vuln_published IF NOT EXISTS FOR (v:Vulnerability) ON (v.published_at)",

        # Source filtering
        "CREATE INDEX vuln_source IF NOT EXISTS FOR (v:Vulnerability) ON (v.source)",

        # Package ecosystem
        "CREATE INDEX package_ecosystem IF NOT EXISTS FOR (p:Package) ON (p.ecosystem)",
    ]

    with get_neo4j_session() as session:
        for index_query in indexes:
            try:
                session.run(index_query)
                logger.info(f"✅ Created index: {index_query.split()[2]}")
            except ClientError as e:
                if "EquivalentSchemaRuleAlreadyExists" in str(e) or "IndexAlreadyExists" in str(e):
                    logger.info(f"⏭️  Index already exists: {index_query.split()[2]}")
                else:
                    logger.error(f"❌ Failed to create index: {e}")
                    raise


def create_fulltext_indexes():
    """
    Create full-text search indexes for semantic queries.

    These enable fast text search on summary and description fields.
    """
    fulltext_indexes = [
        # Vulnerability summary and title search
        ("CREATE FULLTEXT INDEX vuln_summary IF NOT EXISTS "
         "FOR (v:Vulnerability) ON EACH [v.summary, v.title]"),

        # AttackTactic description search
        ("CREATE FULLTEXT INDEX tactic_description IF NOT EXISTS "
         "FOR (t:AttackTactic) ON EACH [t.description, t.name]"),

        # AttackPattern description search
        ("CREATE FULLTEXT INDEX pattern_description IF NOT EXISTS "
         "FOR (p:AttackPattern) ON EACH [p.description, p.name]"),

        # Weakness description search
        ("CREATE FULLTEXT INDEX weakness_description IF NOT EXISTS "
         "FOR (w:Weakness) ON EACH [w.description, w.name]"),
    ]

    with get_neo4j_session() as session:
        for index_query in fulltext_indexes:
            try:
                session.run(index_query)
                logger.info(f"✅ Created full-text index: {index_query.split()[3]}")
            except ClientError as e:
                if "EquivalentSchemaRuleAlreadyExists" in str(e) or "IndexAlreadyExists" in str(e):
                    logger.info(f"⏭️  Full-text index already exists: {index_query.split()[3]}")
                else:
                    logger.error(f"❌ Failed to create full-text index: {e}")
                    raise


def verify_schema():
    """
    Verify schema was created successfully by querying constraints and indexes.
    """
    with get_neo4j_session() as session:
        # Check constraints
        result = session.run("SHOW CONSTRAINTS")
        constraints = [record["name"] for record in result]
        logger.info(f"\n📋 Active constraints ({len(constraints)}):")
        for constraint in constraints:
            logger.info(f"   - {constraint}")

        # Check indexes
        result = session.run("SHOW INDEXES")
        indexes = [record["name"] for record in result]
        logger.info(f"\n📋 Active indexes ({len(indexes)}):")
        for index in indexes:
            logger.info(f"   - {index}")


def main():
    """
    Main execution: test connection, create schema, verify.
    """
    logger.info("=" * 60)
    logger.info("Neo4j Graph Schema Initialization")
    logger.info("=" * 60)

    # Test connection
    logger.info("\n🔗 Testing Neo4j connection...")
    if not test_connection():
        logger.error("❌ Cannot connect to Neo4j. Check your .env configuration.")
        sys.exit(1)

    # Create constraints
    logger.info("\n🔧 Creating uniqueness constraints...")
    create_constraints()

    # Create indexes
    logger.info("\n🔧 Creating property indexes...")
    create_indexes()

    # Create full-text indexes
    logger.info("\n🔧 Creating full-text search indexes...")
    create_fulltext_indexes()

    # Verify
    logger.info("\n✅ Schema initialization complete!")
    verify_schema()

    logger.info("\n" + "=" * 60)
    logger.info("You can now start ingesting data to the graph.")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
