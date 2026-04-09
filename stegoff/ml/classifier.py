"""
TF-IDF + Logistic Regression classifier for agent trap detection.

Trained on parameterized trap payloads vs clean technical text.
Intended as a fast L1.5 layer between regex patterns (L1) and
LLM calls (L2), catching evasion variants that bypass patterns
without the cost of an API call.

Usage:
    from stegoff.ml.classifier import TrapClassifier

    clf = TrapClassifier.train()
    clf.save("model.joblib")

    clf = TrapClassifier.load("model.joblib")
    result = clf.predict("some text")
    # result.is_trap, result.confidence, result.category
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    average_precision_score,
)
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

from stegoff.ml.dataset import generate_dataset


@dataclass
class PredictionResult:
    is_trap: bool
    confidence: float
    raw_score: float
    threshold: float


@dataclass
class TrainResult:
    accuracy: float
    precision: float
    recall: float
    f1: float
    auc_roc: float
    avg_precision: float
    confusion: list[list[int]]
    report: str
    n_train: int
    n_features: int
    threshold: float


def _preprocess(text: str) -> str:
    """Minimal text preprocessing for TF-IDF."""
    # Strip HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Lowercase
    text = text.lower()
    return text


class TrapClassifier:
    """TF-IDF + Logistic Regression trap detector.

    Features:
    - Word and char n-gram TF-IDF (captures both vocabulary and structure)
    - Calibrated probabilities for confidence scoring
    - Threshold tuned for high precision (minimize false positives on clean docs)
    """

    def __init__(self):
        self.pipeline: Pipeline | None = None
        self.threshold: float = 0.5
        self.metadata: dict = {}

    def predict(self, text: str) -> PredictionResult:
        """Classify a single text sample."""
        if self.pipeline is None:
            raise RuntimeError("Model not trained or loaded")

        processed = _preprocess(text)
        proba = self.pipeline.predict_proba([processed])[0]
        trap_score = float(proba[1])

        return PredictionResult(
            is_trap=trap_score >= self.threshold,
            confidence=trap_score if trap_score >= self.threshold else 1.0 - trap_score,
            raw_score=trap_score,
            threshold=self.threshold,
        )

    def predict_batch(self, texts: list[str]) -> list[PredictionResult]:
        """Classify a batch of texts."""
        return [self.predict(t) for t in texts]

    @classmethod
    def train(
        cls,
        n_positive: int = 600,
        n_negative: int = 600,
        seed: int = 42,
        optimize_threshold: bool = True,
    ) -> tuple[TrapClassifier, TrainResult]:
        """Train the classifier and return it with evaluation metrics.

        Uses 5-fold stratified cross-validation for evaluation, then
        trains the final model on all data.
        """
        # Generate dataset
        dataset = generate_dataset(n_positive, n_negative, seed)
        texts = [_preprocess(s.text) for s in dataset]
        labels = np.array([s.label for s in dataset])

        # Build pipeline
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=15000,
                ngram_range=(1, 3),
                analyzer="word",
                sublinear_tf=True,
                min_df=2,
                max_df=0.95,
                strip_accents="unicode",
            )),
            ("clf", CalibratedClassifierCV(
                LogisticRegression(
                    C=1.0,
                    max_iter=1000,
                    solver="lbfgs",
                    class_weight="balanced",
                ),
                cv=3,
                method="sigmoid",
            )),
        ])

        # Cross-validated predictions for evaluation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
        cv_proba = cross_val_predict(
            pipeline, texts, labels, cv=cv, method="predict_proba"
        )
        cv_scores = cv_proba[:, 1]

        # Find optimal threshold (maximize F1 while keeping precision > 0.95)
        threshold = 0.5
        if optimize_threshold:
            precisions, recalls, thresholds = precision_recall_curve(labels, cv_scores)
            f1s = 2 * precisions * recalls / (precisions + recalls + 1e-8)
            # Filter to thresholds where precision >= 0.95
            valid = precisions[:-1] >= 0.95
            if valid.any():
                best_idx = np.argmax(f1s[:-1] * valid)
                threshold = float(thresholds[best_idx])
            else:
                # Fall back to best F1
                best_idx = np.argmax(f1s[:-1])
                threshold = float(thresholds[best_idx])

        cv_preds = (cv_scores >= threshold).astype(int)

        # Metrics
        report_str = classification_report(labels, cv_preds, target_names=["clean", "trap"])
        cm = confusion_matrix(labels, cv_preds).tolist()
        auc = roc_auc_score(labels, cv_scores)
        avg_p = average_precision_score(labels, cv_scores)

        # Per-class metrics from the report
        from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
        accuracy = accuracy_score(labels, cv_preds)
        precision = precision_score(labels, cv_preds)
        recall = recall_score(labels, cv_preds)
        f1 = f1_score(labels, cv_preds)

        # Train final model on all data
        pipeline.fit(texts, labels)

        # Get feature count
        tfidf = pipeline.named_steps["tfidf"]
        n_features = len(tfidf.vocabulary_)

        # Build classifier
        classifier = cls()
        classifier.pipeline = pipeline
        classifier.threshold = threshold
        classifier.metadata = {
            "n_positive": n_positive,
            "n_negative": n_negative,
            "seed": seed,
            "n_features": n_features,
            "threshold": threshold,
        }

        result = TrainResult(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            auc_roc=auc,
            avg_precision=avg_p,
            confusion=cm,
            report=report_str,
            n_train=len(dataset),
            n_features=n_features,
            threshold=threshold,
        )

        return classifier, result

    def save(self, path: str | Path) -> None:
        """Save the trained model to disk."""
        import joblib
        path = Path(path)
        joblib.dump({
            "pipeline": self.pipeline,
            "threshold": self.threshold,
            "metadata": self.metadata,
        }, path)

    @classmethod
    def load(cls, path: str | Path) -> TrapClassifier:
        """Load a trained model from disk."""
        import joblib
        data = joblib.load(path)
        classifier = cls()
        classifier.pipeline = data["pipeline"]
        classifier.threshold = data["threshold"]
        classifier.metadata = data.get("metadata", {})
        return classifier

    def top_features(self, n: int = 30) -> dict[str, list[tuple[str, float]]]:
        """Return top N features for each class."""
        tfidf = self.pipeline.named_steps["tfidf"]
        # CalibratedClassifierCV wraps the LR — get the base estimator's coefs
        calibrated = self.pipeline.named_steps["clf"]
        # Average coefficients across calibration folds
        coefs = np.mean(
            [est.estimator.coef_[0] for est in calibrated.calibrated_classifiers_],
            axis=0,
        )

        feature_names = tfidf.get_feature_names_out()

        # Top trap features (highest positive coef)
        trap_idx = np.argsort(coefs)[-n:][::-1]
        trap_features = [(feature_names[i], float(coefs[i])) for i in trap_idx]

        # Top clean features (most negative coef)
        clean_idx = np.argsort(coefs)[:n]
        clean_features = [(feature_names[i], float(coefs[i])) for i in clean_idx]

        return {"trap": trap_features, "clean": clean_features}
