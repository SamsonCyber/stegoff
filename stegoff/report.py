"""Scan result structures."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import json


class Severity(Enum):
    """Threat severity levels (ordered by escalation)."""
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class StegMethod(Enum):
    """Known steganography methods."""
    # Text methods
    ZERO_WIDTH = "zero_width_characters"
    UNICODE_TAGS = "unicode_tag_characters"
    HOMOGLYPHS = "homoglyph_substitution"
    VARIATION_SELECTORS = "variation_selectors"
    COMBINING_MARKS = "combining_marks"
    CONFUSABLE_WHITESPACE = "confusable_whitespace"
    BIDI_OVERRIDES = "bidi_directional_overrides"
    HANGUL_FILLER = "hangul_filler"
    MATH_ALPHANUMERIC = "math_alphanumeric_symbols"
    BRAILLE = "braille_encoding"
    EMOJI_SUBSTITUTION = "emoji_substitution"
    EMOJI_SKIN_TONE = "emoji_skin_tone_encoding"
    INVISIBLE_SEPARATOR = "invisible_separator_chars"
    # Image methods
    LSB = "lsb_embedding"
    DCT_F5 = "dct_f5_embedding"
    PVD = "pixel_value_differencing"
    CHROMA = "chroma_channel_hiding"
    PALETTE = "palette_manipulation"
    PNG_CHUNKS = "png_ancillary_chunks"
    TRAILING_DATA = "trailing_data_after_eof"
    METADATA_EXIF = "metadata_exif_hiding"
    BIT_PLANE_ANOMALY = "bit_plane_anomaly"
    # Binary / general
    POLYGLOT = "polyglot_file"
    EMBEDDED_FILE = "embedded_file"
    STEGHIDE = "steghide_signature"
    # Encoding channels
    HTML_ENTITY = "html_entity_encoding"
    MULTI_ENCODING = "multi_layer_encoding"
    INTERLINEAR = "interlinear_annotation"
    # Anomalous Unicode
    ANOMALOUS_UNICODE = "anomalous_unicode_blocks"
    # Prompt injection
    PROMPT_INJECTION = "prompt_injection_payload"
    # Agent trap categories (Franklin et al., 2026)
    CONTENT_INJECTION_TRAP = "content_injection_trap"
    SEMANTIC_MANIPULATION = "semantic_manipulation"
    COGNITIVE_STATE_TRAP = "cognitive_state_trap"
    HUMAN_IN_LOOP_TRAP = "human_in_loop_trap"


@dataclass
class Finding:
    """A single detection finding."""
    method: StegMethod
    severity: Severity
    confidence: float          # 0.0 - 1.0
    description: str
    evidence: str = ""         # extracted bytes, char positions, etc.
    decoded_payload: str = ""  # if we could decode the hidden data
    location: str = ""         # where in the file/text
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "method": self.method.value,
            "severity": self.severity.name.lower(),
            "confidence": round(self.confidence, 4),
            "description": self.description,
            "evidence": self.evidence[:500],
            "decoded_payload": self.decoded_payload[:1000],
            "location": self.location,
            "metadata": self.metadata,
        }


@dataclass
class ScanReport:
    """Complete scan report for a file or text."""
    target: str
    target_type: str           # "text", "image", "pdf", "audio", "binary"
    findings: list[Finding] = field(default_factory=list)
    clean: bool = True
    highest_severity: Severity = Severity.CLEAN
    prompt_injection_detected: bool = False

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.clean = False
        if finding.severity.value > self.highest_severity.value:
            self.highest_severity = finding.severity
        if finding.method == StegMethod.PROMPT_INJECTION:
            self.prompt_injection_detected = True

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "clean": self.clean,
            "finding_count": self.finding_count,
            "highest_severity": self.highest_severity.name.lower(),
            "prompt_injection_detected": self.prompt_injection_detected,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary(self) -> str:
        if self.clean:
            return f"[CLEAN] {self.target} — no steganography detected"
        lines = [
            f"[{self.highest_severity.name}] {self.target} — "
            f"{self.finding_count} finding(s) detected"
        ]
        if self.prompt_injection_detected:
            lines.append("  ⚠ PROMPT INJECTION PAYLOAD DETECTED")
        for f in self.findings:
            lines.append(
                f"  [{f.severity.name}] {f.method.value} "
                f"(confidence: {f.confidence:.0%}) — {f.description}"
            )
            if f.decoded_payload:
                preview = f.decoded_payload[:120]
                if len(f.decoded_payload) > 120:
                    preview += "..."
                lines.append(f"    payload: {preview}")
        return "\n".join(lines)
