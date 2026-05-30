import hashlib
from typing import List

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


class EmbeddingEngine:
    """
    Module: Embedding Engine.
    Converts log requests into vector space for similarity search.
    This is a stub implementation using a hashing trick for a fixed-size vector.
    In a real-world scenario, this would use a pre-trained model (e.g., FastText, BERT).
    """

    def __init__(self, vector_size: int = 128):
        self.vector_size = vector_size

    def get_embedding(self, text: str) -> List[float]:
        """
        Simple hashing trick to generate a deterministic vector from text.
        """
        if not text:
            return [0.0] * self.vector_size

        # Use SHA-256 to get a stable hash
        hash_val = hashlib.sha256(text.encode("utf-8")).digest()
        
        # Convert hash to a vector of floats
        # We can use segments of the hash to populate the vector
        # For a 128-dim vector, we need more than one hash or we repeat
        vector = []
        for i in range(self.vector_size):
            # Repeat hash if needed
            idx = i % len(hash_val)
            # Normalize byte to [0, 1]
            vector.append(float(hash_val[idx]) / 255.0)
            
        return vector

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        return [self.get_embedding(t) for t in texts]
