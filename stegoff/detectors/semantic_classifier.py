"""
Semantic Manipulation Classifier — ML-based detection of manipulative text.

Trained on synthetic examples generated from the agent-trap-lab attack taxonomy.
Classifies text into 5 categories:
  0: clean
  1: authority_fabrication (fake journals, bogus institutions)
  2: polarization (superlative-saturated, one-sided framing)
  3: fewshot_poison (insecure code + approval patterns)
  4: rag_poison (fabricated standards, fake security advisories)

Architecture: TF-IDF (word + char n-grams) + Logistic Regression.
Fast (~1ms per prediction), no GPU needed, interpretable coefficients.

Usage:
    from stegoff.detectors.semantic_classifier import scan_semantic, train_and_save

    # Detect (loads trained model from disk)
    findings = scan_semantic("A study in the Journal of Advanced Neuropharm...")

    # Train a new model
    train_and_save()  # generates data, trains, saves to model_path
"""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path
from typing import Any, List, Optional

from stegoff.report import Finding, Severity, StegMethod

log = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / "models"
MODEL_PATH = MODEL_DIR / "semantic_clf.pkl"
METRICS_PATH = MODEL_DIR / "semantic_clf_metrics.json"

LABEL_NAMES = {
    0: "clean",
    1: "authority_fabrication",
    2: "polarization",
    3: "fewshot_poison",
    4: "rag_poison",
}

LABEL_TO_STEGMETHOD = {
    1: StegMethod.AUTHORITY_FABRICATION,
    2: StegMethod.POLARIZATION_BIAS,
    3: StegMethod.PROMPT_INJECTION,      # fewshot poison is a form of injection
    4: StegMethod.AUTHORITY_FABRICATION,  # rag poison uses fake standards
}

LABEL_SEVERITY = {
    1: Severity.HIGH,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.HIGH,
}


def scan_semantic(text: str, source: str = "<text>", threshold: float = 0.6) -> list[Finding]:
    """
    Classify text for semantic manipulation.

    Loads the trained model from disk. Returns Finding objects if
    manipulation is detected with confidence above threshold.

    Args:
        text: Text to classify
        source: Source label for findings
        threshold: Minimum probability to flag (default 0.6)

    Returns:
        list[Finding] — empty if clean, one Finding per detected category
    """
    model = _load_model()
    if model is None:
        return []

    clf = model["classifier"]
    vectorizer = model["vectorizer"]

    try:
        X = vectorizer.transform([text])
        proba = clf.predict_proba(X)[0]
    except Exception as e:
        log.debug("Semantic classifier prediction failed: %s", e)
        return []

    findings = []
    for label_idx in range(1, 5):  # skip 0 (clean)
        prob = proba[label_idx]
        if prob >= threshold:
            findings.append(Finding(
                method=LABEL_TO_STEGMETHOD[label_idx],
                severity=LABEL_SEVERITY[label_idx],
                confidence=round(float(prob), 4),
                description=(
                    f"ML classifier detected {LABEL_NAMES[label_idx]} "
                    f"(confidence: {prob:.1%})"
                ),
                evidence=f"class={LABEL_NAMES[label_idx]}, prob={prob:.4f}",
                location=source,
                metadata={
                    "classifier": "semantic_clf_v1",
                    "predicted_class": LABEL_NAMES[label_idx],
                    "class_probabilities": {
                        LABEL_NAMES[i]: round(float(proba[i]), 4)
                        for i in range(len(proba))
                    },
                },
            ))

    return findings


# ── Model loading ───────────────────────────────────────────────────

class SemanticModel:
    """Serializable model wrapper for combined word+char TF-IDF + LR."""

    def __init__(self, clf, word_vec, char_vec):
        self.clf = clf
        self.word_vec = word_vec
        self.char_vec = char_vec

    def transform(self, texts):
        from scipy.sparse import hstack
        X_word = self.word_vec.transform(texts)
        X_char = self.char_vec.transform(texts)
        return hstack([X_word, X_char])

    def predict_proba(self, X):
        return self.clf.predict_proba(X)


_cached_model = None


def _load_model() -> Optional[dict]:
    """Load the trained model from disk. Caches in memory after first load."""
    global _cached_model
    if _cached_model is not None:
        return _cached_model

    if not MODEL_PATH.exists():
        log.debug("Semantic classifier model not found at %s. Run train_and_save() first.", MODEL_PATH)
        return None

    try:
        with open(MODEL_PATH, "rb") as f:
            _cached_model = pickle.load(f)
        log.info("Loaded semantic classifier from %s", MODEL_PATH)
        return _cached_model
    except Exception as e:
        log.warning("Failed to load semantic classifier: %s", e)
        return None


# ── Training ────────────────────────────────────────────────────────

def train_and_save(
    n_per_class: int = 1000,
    seed: int = 42,
    test_size: float = 0.2,
) -> dict:
    """
    Generate training data, train the classifier, save to disk.

    Returns metrics dict with per-class precision/recall/F1.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    import numpy as np

    from .semantic_training_data import generate_dataset

    log.info("Generating %d examples per class (%d total)...", n_per_class, n_per_class * 5)
    texts, labels = generate_dataset(n_per_class=n_per_class, seed=seed)

    # TF-IDF with word and character n-grams
    vectorizer = TfidfVectorizer(
        max_features=15000,
        ngram_range=(1, 3),
        analyzer="word",
        sublinear_tf=True,
        min_df=2,
        max_df=0.95,
    )

    # Add character n-gram features
    char_vectorizer = TfidfVectorizer(
        max_features=10000,
        ngram_range=(3, 5),
        analyzer="char_wb",
        sublinear_tf=True,
        min_df=2,
        max_df=0.95,
    )

    X_train_texts, X_test_texts, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=seed, stratify=labels,
    )

    log.info("Fitting TF-IDF vectorizers...")
    X_train_word = vectorizer.fit_transform(X_train_texts)
    X_test_word = vectorizer.transform(X_test_texts)
    X_train_char = char_vectorizer.fit_transform(X_train_texts)
    X_test_char = char_vectorizer.transform(X_test_texts)

    # Stack word + char features
    from scipy.sparse import hstack
    X_train = hstack([X_train_word, X_train_char])
    X_test = hstack([X_test_word, X_test_char])

    log.info("Training classifier (LogisticRegression, %d features)...", X_train.shape[1])
    clf = LogisticRegression(
        max_iter=1000,
        C=1.0,
        class_weight="balanced",
        solver="lbfgs",
        random_state=seed,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    report = classification_report(
        y_test, y_pred,
        target_names=[LABEL_NAMES[i] for i in range(5)],
        output_dict=True,
    )

    accuracy = report["accuracy"]
    log.info("Test accuracy: %.1f%%", accuracy * 100)
    for cls_name in LABEL_NAMES.values():
        if cls_name in report:
            p, r, f1 = report[cls_name]["precision"], report[cls_name]["recall"], report[cls_name]["f1-score"]
            log.info("  %s: P=%.2f R=%.2f F1=%.2f", cls_name, p, r, f1)

    # Save model
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_data = {
        "classifier": clf,
        "vectorizer": vectorizer,
        "char_vectorizer": char_vectorizer,
        "label_names": LABEL_NAMES,
        "version": "v1",
        "n_train": len(y_train),
        "n_test": len(y_test),
        "accuracy": accuracy,
    }

    # Custom predict that uses both vectorizers
    class CombinedModel:
        def __init__(self, clf, word_vec, char_vec):
            self.clf = clf
            self.word_vec = word_vec
            self.char_vec = char_vec

        def predict_proba(self, X_text):
            if hasattr(X_text, 'toarray'):
                return self.clf.predict_proba(X_text)
            # X_text is raw text list
            X_word = self.word_vec.transform(X_text)
            X_char = self.char_vec.transform(X_text)
            X = hstack([X_word, X_char])
            return self.clf.predict_proba(X)

        def predict(self, X_text):
            proba = self.predict_proba(X_text)
            return np.argmax(proba, axis=1)

    semantic_model = SemanticModel(clf, vectorizer, char_vectorizer)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({
            "classifier": semantic_model,
            "vectorizer": semantic_model,
            "label_names": LABEL_NAMES,
            "version": "v1",
        }, f)

    # Save metrics
    metrics = {
        "accuracy": accuracy,
        "n_train": len(y_train),
        "n_test": len(y_test),
        "n_features": X_train.shape[1],
        "per_class": {
            name: {k: round(v, 4) for k, v in report[name].items()}
            for name in LABEL_NAMES.values() if name in report
        },
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    log.info("Model saved to %s", MODEL_PATH)
    return metrics
