"""Configurable embedding providers for AegisOps Copilot semantic retrieval."""

import hashlib
import math
import re
from typing import Any, List
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

from aegisops.config import EMBEDDING_PROVIDER


class FastDeterministicEmbeddingFunction(EmbeddingFunction[Documents]):
    """Lightweight, zero-download, deterministic embedding function for tests and air-gapped runs.

    Produces normalized 128-dimensional dense vectors based on term n-gram hashing.
    Preserves semantic overlap for identical and related vocabulary.
    """

    def __init__(self, dim: int = 128):
        self.dim = dim

    @staticmethod
    def name() -> str:
        return "fast_deterministic"

    def get_config(self) -> dict:
        return {"dim": self.dim}

    @classmethod
    def build_from_config(cls, config: dict):
        return cls(dim=config.get("dim", 128))

    def __call__(self, input: Documents) -> Embeddings:
        embeddings: List[List[float]] = []
        for doc in input:
            vec = [0.0] * self.dim
            tokens = re.findall(r"\w+", doc.lower())
            if not tokens:
                embeddings.append(vec)
                continue
            for tok in tokens:
                # 1-gram
                h1 = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16) % self.dim
                vec[h1] += 1.0
                # Character tri-grams for subword similarity
                for i in range(len(tok) - 2):
                    sub = tok[i : i + 3]
                    h2 = int(hashlib.sha1(sub.encode("utf-8")).hexdigest(), 16) % self.dim
                    vec[h2] += 0.5
            # L2 normalize
            norm = math.sqrt(sum(x * x for x in vec))
            if norm > 0:
                vec = [x / norm for x in vec]
            embeddings.append(vec)
        return embeddings


def get_embedding_function(provider: str | None = None) -> Any:
    """Return the configured Chroma-compatible embedding function."""
    chosen = (provider or EMBEDDING_PROVIDER or "default").lower().strip()

    if chosen in ("fast", "fast_local", "deterministic", "test"):
        return FastDeterministicEmbeddingFunction()

    if chosen == "default":
        try:
            from chromadb.utils import embedding_functions

            return embedding_functions.DefaultEmbeddingFunction()
        except Exception:
            # Fallback if onnx/downloads are unavailable
            return FastDeterministicEmbeddingFunction()

    # Sentence Transformers if explicitly requested
    if chosen in ("sentence_transformers", "st"):
        from chromadb.utils import embedding_functions

        return embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )

    # Fallback to default
    try:
        from chromadb.utils import embedding_functions

        return embedding_functions.DefaultEmbeddingFunction()
    except Exception:
        return FastDeterministicEmbeddingFunction()
