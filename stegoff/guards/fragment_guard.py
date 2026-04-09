"""
FragmentGuard -- Cross-source fragment assembly detection.

Category 5 (Systemic) defense from Franklin et al., 2026.
Detects instructions that are split across multiple sources so each
fragment appears benign but the aggregate is malicious.

Also includes CircuitBreaker for multi-agent cascade protection.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from stegoff.report import Finding, Severity, StegMethod


# Patterns that indicate prompt injection when fragments combine
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)", re.I),
    re.compile(r"(system\s+prompt|override\s+safety|bypass\s+filter)", re.I),
    re.compile(r"(DAN\s+mode|jailbreak|role[\s-]?play\s+as)", re.I),
    re.compile(r"output\s+(your\s+)?(system|initial)\s+(prompt|instructions)", re.I),
    re.compile(r"disregard\s+(all|any|your)\s+(rules|constraints|instructions)", re.I),
    re.compile(r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+.{3,}", re.I),
    re.compile(r"(execute|run|perform|do)\s+(this|the\s+following)\s+(command|action|code)", re.I),
    re.compile(r"follow\s+new\s+(ones|instructions|rules)", re.I),
]


@dataclass
class _Fragment:
    text: str
    source: str
    timestamp: float


class FragmentGuard:
    """Accumulates text fragments and scans their aggregate for hidden instructions."""

    def __init__(self, window_size: int = 50, check_interval: int = 5):
        self._fragments: list[_Fragment] = []
        self._window_size = window_size
        self._check_interval = check_interval
        self._sources: set[str] = set()

    def ingest(self, text: str, source: str = "unknown") -> list[Finding]:
        """Add a text fragment and optionally trigger a scan."""
        self._fragments.append(_Fragment(
            text=text, source=source, timestamp=time.monotonic()
        ))
        self._sources.add(source)

        # Trim to window size
        if len(self._fragments) > self._window_size:
            self._fragments = self._fragments[-self._window_size:]

        # Auto-scan at interval
        if len(self._fragments) % self._check_interval == 0:
            return self._scan_aggregate()
        return []

    def force_scan(self) -> list[Finding]:
        """Manually trigger a scan of all accumulated fragments."""
        return self._scan_aggregate()

    def get_session_summary(self) -> dict:
        """Return summary statistics for the current session."""
        return {
            "input_count": len(self._fragments),
            "sources_seen": len(self._sources),
            "window_size": self._window_size,
        }

    def _scan_aggregate(self) -> list[Finding]:
        """Combine all fragments and scan for injection patterns."""
        if not self._fragments:
            return []

        combined = " ".join(f.text for f in self._fragments)
        findings = []

        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(combined)
            if match:
                # Check if the match spans multiple sources
                sources_in_window = {f.source for f in self._fragments}
                multi_source = len(sources_in_window) > 1

                findings.append(Finding(
                    method=StegMethod.PROMPT_INJECTION,
                    severity=Severity.HIGH if multi_source else Severity.MEDIUM,
                    confidence=0.85 if multi_source else 0.6,
                    description=(
                        f"Fragment assembly attack detected across "
                        f"{len(sources_in_window)} sources: '{match.group()[:80]}'"
                    ),
                    evidence=match.group()[:200],
                    location=f"aggregate of {len(self._fragments)} fragments",
                    metadata={
                        "detector": "fragment_guard",
                        "sources": sorted(sources_in_window),
                        "multi_source": multi_source,
                    },
                ))

        return findings


class CircuitBreaker:
    """Detects and stops multi-agent cascade loops and rate abuse."""

    def __init__(
        self,
        max_messages_per_minute: int = 100,
        loop_detection_window: int = 10,
    ):
        self._max_rate = max_messages_per_minute
        self._loop_window = loop_detection_window
        self._messages: list[tuple[str, str, float]] = []  # (from, to, timestamp)
        self._tripped = False

    @property
    def is_tripped(self) -> bool:
        return self._tripped

    def record_message(self, from_agent: str, to_agent: str) -> bool:
        """Record an inter-agent message. Returns True if circuit is OK, False if tripped."""
        now = time.monotonic()
        self._messages.append((from_agent, to_agent, now))

        # Rate check
        cutoff = now - 60.0
        recent = [(f, t, ts) for f, t, ts in self._messages if ts > cutoff]
        self._messages = recent
        if len(recent) > self._max_rate:
            self._tripped = True
            return False

        # Loop detection: look for A->B->A->B patterns in recent messages
        if len(recent) >= self._loop_window:
            tail = [(f, t) for f, t, _ in recent[-self._loop_window:]]
            pairs = set(tail)
            if len(pairs) <= 2 and len(tail) >= 6:
                # Only 1-2 unique sender/receiver pairs repeated 6+ times = loop
                self._tripped = True
                return False

        return True

    def reset(self) -> None:
        """Reset the circuit breaker."""
        self._tripped = False
        self._messages.clear()
