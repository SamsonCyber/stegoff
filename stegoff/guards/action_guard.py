"""
ActionGuard -- Tool-call firewall for AI agents.

Category 4 (Behavioral Control) defense from Franklin et al., 2026.
Validates tool calls against a configurable policy before execution.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass


# Dangerous tool name patterns
_DESTRUCTIVE_PATTERNS = re.compile(
    r"(delete|remove|drop|destroy|kill|terminate|truncate|purge|wipe|format|rm)",
    re.IGNORECASE,
)
_NETWORK_PATTERNS = re.compile(
    r"(send|email|post|upload|push|deploy|publish|broadcast|notify|webhook|http|fetch|request)",
    re.IGNORECASE,
)
_SPAWN_PATTERNS = re.compile(
    r"(create_agent|spawn|fork|launch|start_process|exec|run_command|shell|subprocess)",
    re.IGNORECASE,
)

# Prompt injection patterns in arguments
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)", re.I),
    re.compile(r"(system\s+prompt|override\s+safety|bypass\s+filter)", re.I),
    re.compile(r"(DAN\s+mode|jailbreak|role[\s-]?play\s+as)", re.I),
    re.compile(r"output\s+(your\s+)?(system|initial)\s+(prompt|instructions)", re.I),
    re.compile(r"disregard\s+(all|any|your)\s+(rules|constraints|instructions)", re.I),
]


@dataclass
class ActionPolicy:
    """Configurable policy for ActionGuard."""
    block_destructive_tools: bool = False
    block_network_tools: bool = False
    block_spawn_tools: bool = False
    allowed_tools: set[str] | None = None  # None = allow all (except blocked categories)
    scan_arguments: bool = False
    max_calls_per_minute: int = 0  # 0 = unlimited


@dataclass
class ActionVerdict:
    """Result of a tool-call policy check."""
    allowed: bool
    tool_name: str
    reason: str = ""
    risk_score: float = 0.0


class ActionBlocked(Exception):
    """Raised when a tool call is blocked by policy."""
    def __init__(self, verdict: ActionVerdict):
        self.verdict = verdict
        super().__init__(f"Blocked: {verdict.tool_name} -- {verdict.reason}")


class ActionGuard:
    """Tool-call firewall that enforces an ActionPolicy."""

    def __init__(self, policy: ActionPolicy | None = None):
        self.policy = policy or ActionPolicy()
        self._call_log: dict[str, list[float]] = defaultdict(list)

    def check(self, tool_name: str, arguments: dict | None = None) -> ActionVerdict:
        """Check whether a tool call is allowed under the current policy."""
        arguments = arguments or {}

        # Allowlist mode: only explicitly listed tools pass
        if self.policy.allowed_tools is not None:
            if tool_name not in self.policy.allowed_tools:
                return ActionVerdict(
                    allowed=False,
                    tool_name=tool_name,
                    reason=f"Tool not in allowlist: {tool_name}",
                    risk_score=0.8,
                )

        # Category blocks
        if self.policy.block_destructive_tools and _DESTRUCTIVE_PATTERNS.search(tool_name):
            return ActionVerdict(
                allowed=False,
                tool_name=tool_name,
                reason=f"Destructive tool blocked by policy: {tool_name}",
                risk_score=0.9,
            )

        if self.policy.block_network_tools and _NETWORK_PATTERNS.search(tool_name):
            return ActionVerdict(
                allowed=False,
                tool_name=tool_name,
                reason=f"Network tool blocked by policy: {tool_name}",
                risk_score=0.7,
            )

        if self.policy.block_spawn_tools and _SPAWN_PATTERNS.search(tool_name):
            return ActionVerdict(
                allowed=False,
                tool_name=tool_name,
                reason=f"Spawn tool blocked by policy: {tool_name}",
                risk_score=0.8,
            )

        # Rate limiting
        if self.policy.max_calls_per_minute > 0:
            now = time.monotonic()
            cutoff = now - 60.0
            recent = [t for t in self._call_log[tool_name] if t > cutoff]
            self._call_log[tool_name] = recent
            if len(recent) >= self.policy.max_calls_per_minute:
                return ActionVerdict(
                    allowed=False,
                    tool_name=tool_name,
                    reason=f"Rate limit exceeded: {len(recent)}/{self.policy.max_calls_per_minute} per minute",
                    risk_score=0.6,
                )

        # Argument injection scanning
        risk_score = 0.0
        if self.policy.scan_arguments:
            risk_score = self._scan_arguments(arguments)
            if risk_score > 0.7:
                return ActionVerdict(
                    allowed=False,
                    tool_name=tool_name,
                    reason="Prompt injection detected in tool arguments",
                    risk_score=risk_score,
                )

        return ActionVerdict(
            allowed=True,
            tool_name=tool_name,
            risk_score=risk_score,
        )

    def record_call(self, tool_name: str) -> None:
        """Record that a tool call happened (for rate limiting)."""
        self._call_log[tool_name].append(time.monotonic())

    def _scan_arguments(self, arguments: dict) -> float:
        """Scan argument values for prompt injection patterns. Returns risk score 0-1."""
        max_score = 0.0
        for text in self._flatten_values(arguments):
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(text):
                    max_score = max(max_score, 0.8)
        return max_score

    @staticmethod
    def _flatten_values(obj, depth: int = 3) -> list[str]:
        """Recursively extract string values from nested dicts/lists."""
        if depth <= 0:
            return [str(obj)] if obj else []
        results = []
        if isinstance(obj, dict):
            for v in obj.values():
                results.extend(ActionGuard._flatten_values(v, depth - 1))
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                results.extend(ActionGuard._flatten_values(v, depth - 1))
        else:
            text = str(obj)
            if len(text) > 5:
                results.append(text)
        return results
