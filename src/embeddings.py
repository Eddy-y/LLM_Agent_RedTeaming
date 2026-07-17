"""
Generate embeddings using AWS Bedrock Titan Embeddings model.

Provides vector representations of text for semantic search in PostgreSQL pgvector.
"""

import json
import logging
from typing import List, Optional

import boto3
from botocore.exceptions import ClientError

try:
    from config import get_settings
except ImportError:
    from src.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Initialize Bedrock runtime client
_bedrock_runtime = None


def get_bedrock_runtime():
    """
    Get or create Bedrock runtime client.

    Returns:
        Boto3 Bedrock runtime client
    """
    global _bedrock_runtime

    if _bedrock_runtime is None:
        session = boto3.Session(profile_name=settings.aws_profile_name)
        # Titan Embeddings v1 is only available in us-east-1
        _bedrock_runtime = session.client(
            service_name='bedrock-runtime',
            region_name='us-east-1'
        )
        logger.info("Initialized Bedrock runtime client in us-east-1")

    return _bedrock_runtime


def generate_embedding(text: str, model_id: str = "amazon.titan-embed-text-v1") -> Optional[List[float]]:
    """
    Generate embedding vector from text using AWS Bedrock Titan Embeddings.

    Args:
        text: Input text to embed (max 8192 tokens for Titan v1)
        model_id: Bedrock model ID (default: amazon.titan-embed-text-v1)

    Returns:
        List of 1536 floats representing the embedding vector, or None on error

    Raises:
        ClientError: On Bedrock API errors (throttling, invalid input, etc.)
    """
    if not text or not text.strip():
        logger.warning("Empty text provided for embedding generation")
        return None

    # Truncate text if too long (Titan v1 max: 8192 tokens ≈ 30,000 chars)
    max_chars = 30000
    if len(text) > max_chars:
        logger.debug(f"Truncating text from {len(text)} to {max_chars} chars")
        text = text[:max_chars]

    try:
        bedrock_runtime = get_bedrock_runtime()

        request_body = json.dumps({
            "inputText": text
        })

        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=request_body
        )

        response_body = json.loads(response['body'].read())
        embedding = response_body.get('embedding')

        if embedding and len(embedding) == 1536:
            return embedding
        else:
            logger.error(f"Unexpected embedding format: {type(embedding)}, length={len(embedding) if embedding else 0}")
            return None

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']

        if error_code == 'ThrottlingException':
            logger.warning(f"Bedrock throttling: {error_message}")
        elif error_code == 'ValidationException':
            logger.error(f"Invalid input for embedding: {error_message}")
        else:
            logger.error(f"Bedrock error ({error_code}): {error_message}")

        raise

    except Exception as e:
        logger.error(f"Unexpected error generating embedding: {e}")
        return None


def generate_embeddings_batch(texts: List[str], model_id: str = "amazon.titan-embed-text-v1") -> List[Optional[List[float]]]:
    """
    Generate embeddings for a batch of texts.

    Note: Titan Embeddings v1 doesn't support native batching, so this
    makes sequential API calls. Consider rate limiting for large batches.

    Args:
        texts: List of input texts
        model_id: Bedrock model ID

    Returns:
        List of embedding vectors (same length as input, None for failures)
    """
    embeddings = []

    for i, text in enumerate(texts):
        try:
            embedding = generate_embedding(text, model_id)
            embeddings.append(embedding)

            # Log progress for large batches
            if (i + 1) % 10 == 0:
                logger.info(f"Generated {i + 1}/{len(texts)} embeddings")

        except ClientError as e:
            logger.error(f"Failed to generate embedding for text {i}: {e}")
            embeddings.append(None)

    logger.info(f"Batch complete: {sum(1 for e in embeddings if e is not None)}/{len(texts)} successful")

    return embeddings


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """
    Calculate cosine similarity between two embedding vectors.

    Args:
        vec1: First embedding vector
        vec2: Second embedding vector

    Returns:
        Cosine similarity score (0 to 1, higher = more similar)
    """
    if len(vec1) != len(vec2):
        raise ValueError(f"Vector length mismatch: {len(vec1)} vs {len(vec2)}")

    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = sum(a * a for a in vec1) ** 0.5
    norm2 = sum(b * b for b in vec2) ** 0.5

    if norm1 == 0 or norm2 == 0:
        return 0.0

    return dot_product / (norm1 * norm2)
