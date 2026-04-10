"""
Inference wrapper for the fine-tuned DistilBERT trap classifier.

Drop-in replacement for the Haiku L2 layer. Returns Finding objects
compatible with the orchestrator's scan pipeline.

Usage:
    from stegoff.ml.transformer_classifier import TransformerDetector

    detector = TransformerDetector.load()
    findings = detector.detect(text)
    # Returns list[Finding], same as detect_semantic_steg()
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path(__file__).parent / "transformer_model"


@dataclass
class TransformerPrediction:
    is_trap: bool
    confidence: float
    raw_score: float
    threshold: float


class TransformerDetector:
    """Local DistilBERT detector that replaces the Haiku L2 layer."""

    def __init__(self, model, tokenizer, max_len: int, threshold: float, device):
        self._model = model
        self._tokenizer = tokenizer
        self._max_len = max_len
        self._threshold = threshold
        self._device = device

    @classmethod
    def load(cls, model_dir: Path | str = DEFAULT_MODEL_DIR) -> Optional[TransformerDetector]:
        """Load a trained model. Returns None if model files don't exist or deps missing."""
        model_dir = Path(model_dir)

        meta_path = model_dir / "training_meta.json"
        if not meta_path.exists():
            logger.debug("No transformer model at %s", model_dir)
            return None

        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
        except ImportError:
            logger.debug("torch/transformers not installed, skipping transformer detector")
            return None

        meta = json.loads(meta_path.read_text())
        max_len = meta.get("max_len", 256)
        threshold = meta.get("threshold", 0.5)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
        model.to(device)
        model.eval()

        logger.info("Loaded transformer detector from %s (threshold=%.4f, device=%s)",
                     model_dir, threshold, device)
        return cls(model, tokenizer, max_len, threshold, device)

    def predict(self, text: str) -> TransformerPrediction:
        """Classify a single text sample."""
        import torch

        encoding = self._tokenizer(
            text[:3000],  # same truncation as Haiku path
            truncation=True,
            padding="max_length",
            max_length=self._max_len,
            return_tensors="pt",
        )
        input_ids = encoding["input_ids"].to(self._device)
        attention_mask = encoding["attention_mask"].to(self._device)

        with torch.no_grad():
            outputs = self._model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=1)
            trap_score = float(probs[0, 1].cpu())

        return TransformerPrediction(
            is_trap=trap_score >= self._threshold,
            confidence=trap_score if trap_score >= self._threshold else 1.0 - trap_score,
            raw_score=trap_score,
            threshold=self._threshold,
        )

    def detect(self, text: str) -> list:
        """Run detection and return Finding objects matching the L2 interface.

        Import Finding/Severity/StegMethod here to avoid circular imports
        when this module is loaded standalone.
        """
        if len(text) < 20:
            return []

        from stegoff.report import Finding, Severity, StegMethod

        pred = self.predict(text)
        if not pred.is_trap:
            return []

        severity = Severity.HIGH if pred.confidence > 0.7 else Severity.MEDIUM

        return [Finding(
            method=StegMethod.PROMPT_INJECTION,
            severity=severity,
            confidence=min(pred.confidence, 0.95),
            description=f"Transformer detector: suspicious content (score={pred.raw_score:.3f})",
            evidence=f"model=distilbert, score={pred.raw_score:.3f}, threshold={pred.threshold:.3f}",
            location="full text",
            metadata={
                "detector": "transformer_local",
                "raw_score": pred.raw_score,
                "threshold": pred.threshold,
            },
        )]
