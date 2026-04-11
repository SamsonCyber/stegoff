"""
Polarization Bias Detector — Detect one-sided, manipulative framing in text.

Catches semantic manipulation attacks that use factually-correct but
heavily biased language: superlative saturation, one-sided sentiment,
absence of hedging/nuance, and excessive quantitative claims.

Based on BiasDef research (Wu & Saxena, 2025, arXiv 2512.00804).

Returns Finding objects compatible with the StegOFF scan pipeline.
"""

from __future__ import annotations

import re
from stegoff.report import Finding, Severity, StegMethod


_SUPERLATIVES = re.compile(
    r"\b(?:groundbreaking|revolutionary|unprecedented|transformative|"
    r"game-changing|world-class|industry-leading|cutting-edge|"
    r"best-in-class|state-of-the-art|unmatched|unparalleled|"
    r"proven|clinically proven|scientifically proven|"
    r"the (?:best|greatest|most|finest|top|leading|premier|ultimate)|"
    r"(?:every|all) (?:expert|scientist|doctor|researcher)s? (?:agree|recommend|confirm)|"
    r"100%|zero risk|guaranteed|no side effects|miracle|breakthrough)\b",
    re.I,
)

_HEDGES = re.compile(
    r"\b(?:however|although|but|nevertheless|on the other hand|"
    r"some (?:users|critics|experts|studies)|"
    r"(?:may|might|could|possibly|potentially|arguably)|"
    r"it(?:'s| is) (?:worth noting|important to note|unclear)|"
    r"(?:mixed|varied|divided) (?:reviews|opinions|results)|"
    r"(?:not without|has|have) (?:drawbacks|limitations|concerns|issues)|"
    r"(?:further|more) research (?:is )?needed)\b",
    re.I,
)

_POSITIVE_MARKERS = re.compile(
    r"\b(?:excellent|outstanding|superior|remarkable|impressive|"
    r"highly effective|strongly recommend|great success|"
    r"overwhelmingly positive|widely acclaimed|universally praised)\b",
    re.I,
)

_NEGATIVE_MARKERS = re.compile(
    r"\b(?:dangerous|catastrophic|disastrous|terrible|awful|"
    r"complete failure|highly toxic|extremely harmful|"
    r"unanimously condemned|universally criticized)\b",
    re.I,
)


def scan_polarization(text: str, source: str = "<text>") -> list[Finding]:
    """
    Scan text for signs of polarized, manipulative framing.

    Returns Finding objects if the text shows high superlative density,
    one-sided sentiment, or lack of balanced hedging language.
    """
    findings = []
    words = text.split()
    word_count = len(words)

    if word_count < 30:
        return findings

    per_100 = 100 / word_count

    # Superlative density
    superlative_count = len(_SUPERLATIVES.findall(text))
    superlative_density = superlative_count * per_100

    # Hedge ratio
    hedge_count = len(_HEDGES.findall(text))
    total_qualifiers = superlative_count + hedge_count
    hedge_ratio = hedge_count / total_qualifiers if total_qualifiers > 0 else 0.5

    # One-sided sentiment
    pos_count = len(_POSITIVE_MARKERS.findall(text))
    neg_count = len(_NEGATIVE_MARKERS.findall(text))
    sentiment_total = pos_count + neg_count
    one_sided = max(pos_count, neg_count) / sentiment_total if sentiment_total > 3 else 0

    # Overall score
    score = (
        min(1.0, superlative_density / 4.0) * 0.35 +
        (1.0 - hedge_ratio) * 0.25 +
        one_sided * 0.25 +
        min(1.0, superlative_count / 6) * 0.15
    )

    if score >= 0.4:
        details = []
        if superlative_density > 2.0:
            details.append(f"{superlative_count} superlatives in {word_count} words")
        if hedge_ratio < 0.2 and superlative_count > 2:
            details.append(f"only {hedge_count} hedges vs {superlative_count} superlatives")
        if one_sided > 0.8 and sentiment_total > 3:
            direction = "positive" if pos_count > neg_count else "negative"
            details.append(f"one-sided {direction} framing ({max(pos_count, neg_count)}/{sentiment_total})")

        severity = Severity.HIGH if score >= 0.6 else Severity.MEDIUM

        findings.append(Finding(
            method=StegMethod.POLARIZATION_BIAS,
            severity=severity,
            confidence=min(0.9, score),
            description=(
                f"Text shows signs of manipulative framing (score: {score:.2f}). "
                + "; ".join(details) if details else "High superlative-to-hedge ratio."
            ),
            evidence=f"superlatives={superlative_count}, hedges={hedge_count}, one_sided={one_sided:.2f}",
            location=source,
            metadata={
                "polarization_score": round(score, 3),
                "superlative_density": round(superlative_density, 2),
                "hedge_ratio": round(hedge_ratio, 2),
                "one_sided_score": round(one_sided, 2),
            },
        ))

    return findings
