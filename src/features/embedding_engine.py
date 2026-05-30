from __future__ import annotations
import logging
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
    This implementation uses a pre-trained SentenceTransformer model (e.g. all-MiniLM-L6-v2)
    to generate semantic vectors from log lines.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2", device: Optional[str] = None):
        self.model_name = model_name
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
            # sentence-transformers modern API uses get_embedding_dimension
            if hasattr(self.model, "get_embedding_dimension"):
                self._vector_size = self.model.get_embedding_dimension()
            else:
                self._vector_size = self.model.get_sentence_embedding_dimension()
        return self._vector_size

    def get_embedding(self, text: str) -> List[float]:
        """
        Generate semantic vector embedding for a single text.
        """
        if not text:
            # If not loaded yet, try to get default vector size, default to 384 for all-MiniLM-L6-v2
            dim = self.vector_size if HAS_SENTENCE_TRANSFORMERS else 384
            return [0.0] * dim

        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Generate semantic vector embeddings for a list of texts in batch.
        """
        if not texts:
            return []

        embeddings = self.model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()
