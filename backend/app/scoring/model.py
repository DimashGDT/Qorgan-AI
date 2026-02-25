"""
ML model interface.

Currently a stub that returns 0 (no-op).
Replace `_load_model` and `predict` with a real model
(e.g. scikit-learn, ONNX Runtime, or a local LLM call).
"""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)

MODEL_VERSION = "rules-v1.0"


class ScamModel:
    def __init__(self) -> None:
        self._model = self._load_model()

    def _load_model(self):
        """Load model weights / artifacts. Returns None for stub."""
        logger.info("ML model not configured – using rules-only scoring")
        return None

    def predict(self, features: dict) -> float:
        """
        Return a float score in [0, 1] representing scam probability.
        Stub: always returns 0.0 (rules engine provides full score).

        To integrate a real model:
            return self._model.predict_proba([feature_vector])[0][1]
        """
        if self._model is None:
            return 0.0
        # real inference would go here
        return 0.0  # pragma: no cover


# Singleton
_model_instance: ScamModel | None = None


def get_model() -> ScamModel:
    global _model_instance
    if _model_instance is None:
        _model_instance = ScamModel()
    return _model_instance
