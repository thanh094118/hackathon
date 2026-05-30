from __future__ import annotations
import logging
import hashlib
from typing import List, Optional

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False


class EmbeddingEngine:
    """
    Module: Embedding Engine.
    Converts log requests into vector space for similarity search.
    If sentence-transformers is installed, uses a pre-trained model (e.g. all-MiniLM-L6-v2)
    to generate semantic vectors from log lines. Otherwise, falls back to a deterministic
    hashing trick to generate fixed-size vectors.
    """

    def __init__(
        self,
        model_name_or_vector_size = "all-MiniLM-L6-v2",
        device: Optional[str] = None,
        vector_size: Optional[int] = None
    ):
        if isinstance(model_name_or_vector_size, int):
            self.vector_size_override = model_name_or_vector_size
            self.model_name = "all-MiniLM-L6-v2"
        else:
            self.model_name = model_name_or_vector_size
            self.vector_size_override = vector_size
        self.device = device
        self._model: Optional[SentenceTransformer] = None
        self._vector_size: Optional[int] = None

    @property
    def model(self) -> SentenceTransformer:
        if not HAS_SENTENCE_TRANSFORMERS:
            raise ImportError(
                "sentence-transformers is not installed. Please run `pip install sentence-transformers`."
            )
        if self._model is None:
            logging.info(f"Loading SentenceTransformer model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name, device=self.device)
        return self._model

    @property
    def vector_size(self) -> int:
        if self._vector_size is None:
            if self.vector_size_override is not None:
                self._vector_size = self.vector_size_override
            elif HAS_SENTENCE_TRANSFORMERS:
                try:
                    if hasattr(self.model, "get_embedding_dimension"):
                        self._vector_size = self.model.get_embedding_dimension()
                    else:
                        self._vector_size = self.model.get_sentence_embedding_dimension()
                except Exception:
                    self._vector_size = 384
            else:
                self._vector_size = 384
        return self._vector_size

    def get_embedding(self, text: str) -> List[float]:
        """
        Generate semantic vector embedding for a single text.
        Falls back to a hashing trick if sentence-transformers is not available.
        """
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                if not text:
                    dim = self.vector_size
                    return [0.0] * dim
                embedding = self.model.encode(text, convert_to_numpy=True)
                return embedding.tolist()
            except Exception as e:
                logging.warning(f"SentenceTransformer failed, falling back to hashing trick: {e}")
        
        # Hashing trick fallback
        size = self.vector_size
        if not text:
            return [0.0] * size
            
        hash_val = hashlib.sha256(text.encode("utf-8")).digest()
        vector = []
        for i in range(size):
            idx = i % len(hash_val)
            vector.append(float(hash_val[idx]) / 255.0)
        return vector

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Generate semantic vector embeddings for a list of texts in batch.
        """
        if not texts:
            return []
            
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                embeddings = self.model.encode(texts, convert_to_numpy=True)
                return embeddings.tolist()
            except Exception as e:
                logging.warning(f"SentenceTransformer batch encode failed, falling back to hashing: {e}")
                
        return [self.get_embedding(t) for t in texts]
