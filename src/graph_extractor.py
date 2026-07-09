"""
Graph entity and relationship extraction from normalized threat intelligence records.

Converts normalized data from specialist agents into Neo4j-compatible node and edge structures.
Includes validation to prevent hallucinated relationships.
"""

import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


def infer_node_type(record_type: str) -> str:
    """
    Map record_type to Neo4j node label.

    Args:
        record_type: Record type from normalized data (e.g., "CVE", "MITRE", "CAPEC")

    Returns:
        Neo4j node label (e.g., "Vulnerability", "AttackTactic")
    """
    mapping = {
        "CVE": "Vulnerability",
        "GHSA": "Vulnerability",
        "MITRE": "AttackTactic",
        "CAPEC": "AttackPattern",
        "Package": "Package",
        "CWE": "Weakness"
    }
    return mapping.get(record_type, "Entity")


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


def validate_relationship_triple(triple: Dict[str, Any]) -> bool:
    """
    Validate extracted relationship triple structure and content.

    Prevents hallucinated or malformed relationships from entering the graph.
    Enforces strict ID format validation and allowed relationship types.

    Args:
        triple: Relationship dictionary with subject, predicate, object, types

    Returns:
        True if valid, False if hallucinated or malformed
    """
    required_fields = ["subject", "subject_type", "predicate", "object", "object_type"]
    if not all(field in triple for field in required_fields):
        logger.debug(f"Missing required fields in relationship: {triple}")
        return False

    # Validate ID formats
    subject = str(triple["subject"])
    object_val = str(triple["object"])

    # CVE format check (CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx)
    if triple["subject_type"] == "Vulnerability":
        if not re.match(r'^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$', subject):
            logger.debug(f"Invalid Vulnerability ID format: {subject}")
            return False

    if triple["object_type"] == "Vulnerability":
        if not re.match(r'^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$', object_val):
            logger.debug(f"Invalid Vulnerability ID format: {object_val}")
            return False

    # CWE format check (CWE-NNN)
    if triple["object_type"] == "Weakness":
        if not re.match(r'^CWE-\d+$', object_val):
            logger.debug(f"Invalid CWE ID format: {object_val}")
            return False

    if triple["subject_type"] == "Weakness":
        if not re.match(r'^CWE-\d+$', subject):
            logger.debug(f"Invalid CWE ID format: {subject}")
            return False

    # MITRE format check (T#### or TA#### or T####.###)
    if triple["object_type"] == "AttackTactic":
        if not re.match(r'^T[A]?\d{4}(\.\d{3})?$', object_val):
            logger.debug(f"Invalid MITRE tactic ID format: {object_val}")
            return False

    if triple["subject_type"] == "AttackTactic":
        if not re.match(r'^T[A]?\d{4}(\.\d{3})?$', subject):
            logger.debug(f"Invalid MITRE tactic ID format: {subject}")
            return False

    # CAPEC format check (CAPEC-NNN)
    if triple["object_type"] == "AttackPattern":
        if not re.match(r'^CAPEC-\d+$', object_val):
            logger.debug(f"Invalid CAPEC ID format: {object_val}")
            return False

    if triple["subject_type"] == "AttackPattern":
        if not re.match(r'^CAPEC-\d+$', subject):
            logger.debug(f"Invalid CAPEC ID format: {subject}")
            return False

    # Validate predicate is in allowed set
    allowed_predicates = {
        "EXPLOITS", "AFFECTS", "ENABLES", "IMPLEMENTS", "TARGETS",
        "MITIGATES", "REMEDIATES", "SUB_TECHNIQUE_OF", "CHILD_OF",
        "DEPENDS_ON", "HAS_VULNERABILITY", "REFERENCED_BY", "RELATED_TO"
    }
    if triple["predicate"] not in allowed_predicates:
        logger.debug(f"Invalid predicate: {triple['predicate']}")
        return False

    return True


def extract_graph_entities(
    normalized_records: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convert normalized records and extracted relationships into Neo4j MERGE-ready structures.

    Args:
        normalized_records: List of normalized threat intel records from central normalizer
        relationships: List of relationship triples extracted by specialist agents

    Returns:
        Dictionary with "nodes" and "relationships" keys:
            {
                "nodes": [{"type": "Vulnerability", "properties": {...}}, ...],
                "relationships": [{"type": "AFFECTS", "from_node": {...}, "to_node": {...}, "properties": {...}}, ...]
            }
    """
    nodes = []
    edges = []

    # Extract nodes from normalized records
    for record in normalized_records:
        node_type = infer_node_type(record.get("record_type", ""))

        # Build node properties from normalized data
        properties = {
            get_id_field(node_type): record.get("canonical_id"),
            "title": record.get("title"),
            "summary": record.get("summary"),
            "severity": record.get("severity"),
            "published_at": record.get("published_at"),
            "source": record.get("source")
        }

        # Remove None values
        properties = {k: v for k, v in properties.items() if v is not None}

        node = {
            "type": node_type,
            "properties": properties
        }
        nodes.append(node)

    logger.info(f"Extracted {len(nodes)} nodes from normalized records")

    # Extract relationships with validation
    validated_count = 0
    for rel in relationships:
        if validate_relationship_triple(rel):
            edge = {
                "type": rel["predicate"],
                "from_node": {
                    "type": rel["subject_type"],
                    "id_field": get_id_field(rel["subject_type"]),
                    "id_value": rel["subject"]
                },
                "to_node": {
                    "type": rel["object_type"],
                    "id_field": get_id_field(rel["object_type"]),
                    "id_value": rel["object"]
                },
                "properties": rel.get("properties", {})
            }
            edges.append(edge)
            validated_count += 1
        else:
            logger.warning(f"Rejected invalid relationship triple: {rel}")

    logger.info(f"Validated {validated_count}/{len(relationships)} relationship triples")

    return {
        "nodes": nodes,
        "relationships": edges
    }


def create_package_node(package_name: str, ecosystem: str = "pypi") -> Dict[str, Any]:
    """
    Create a Package node structure.

    Helper function for creating package nodes when not present in normalized data.

    Args:
        package_name: Name of the package
        ecosystem: Package ecosystem (default: "pypi")

    Returns:
        Node dictionary ready for Neo4j insertion
    """
    return {
        "type": "Package",
        "properties": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }


def create_cwe_node(cwe_id: str, name: str = None, description: str = None) -> Dict[str, Any]:
    """
    Create a Weakness (CWE) node structure.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-89")
        name: Optional CWE name
        description: Optional CWE description

    Returns:
        Node dictionary ready for Neo4j insertion
    """
    properties = {"cwe_id": cwe_id}

    if name:
        properties["name"] = name
    if description:
        properties["description"] = description

    return {
        "type": "Weakness",
        "properties": properties
    }
