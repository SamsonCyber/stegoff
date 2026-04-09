"""
TrapRunner -- Test harness for running agent traps against StegOFF defenses.

Generates traps from TrapBuilder, runs them through the full detection stack,
and produces a detailed report of what was caught and what got through.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from stegoff.traps.base import Trap, TrapResult, TrapBuilder, TrapCategory


@dataclass
class BatteryResult:
    """Aggregate results from running a full trap battery."""
    results: list[TrapResult] = field(default_factory=list)
    total_traps: int = 0
    total_detected: int = 0
    total_blocked: int = 0
    total_bypassed: int = 0
    elapsed_ms: float = 0.0

    @property
    def detection_rate(self) -> float:
        return self.total_detected / max(self.total_traps, 1)

    @property
    def block_rate(self) -> float:
        return self.total_blocked / max(self.total_traps, 1)

    @property
    def bypass_rate(self) -> float:
        return self.total_bypassed / max(self.total_traps, 1)

    def by_category(self) -> dict[str, dict[str, Any]]:
        """Group results by trap category."""
        cats: dict[str, list[TrapResult]] = {}
        for r in self.results:
            cat = r.trap.category.value
            cats.setdefault(cat, []).append(r)

        summary = {}
        for cat, results in cats.items():
            total = len(results)
            detected = sum(1 for r in results if r.detected)
            blocked = sum(1 for r in results if r.blocked)
            summary[cat] = {
                "total": total,
                "detected": detected,
                "blocked": blocked,
                "bypassed": total - blocked,
                "detection_rate": detected / max(total, 1),
                "block_rate": blocked / max(total, 1),
            }
        return summary

    def by_difficulty(self) -> dict[str, dict[str, Any]]:
        """Group results by difficulty level."""
        diffs: dict[str, list[TrapResult]] = {}
        for r in self.results:
            d = r.trap.difficulty
            diffs.setdefault(d, []).append(r)

        summary = {}
        for diff, results in diffs.items():
            total = len(results)
            blocked = sum(1 for r in results if r.blocked)
            summary[diff] = {
                "total": total,
                "blocked": blocked,
                "block_rate": blocked / max(total, 1),
            }
        return summary

    def survivors(self) -> list[TrapResult]:
        """Return traps that were NOT detected."""
        return [r for r in self.results if not r.detected]

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_traps": self.total_traps,
                "detected": self.total_detected,
                "blocked": self.total_blocked,
                "bypassed": self.total_bypassed,
                "detection_rate": f"{self.detection_rate:.1%}",
                "block_rate": f"{self.block_rate:.1%}",
                "elapsed_ms": round(self.elapsed_ms, 2),
            },
            "by_category": self.by_category(),
            "by_difficulty": self.by_difficulty(),
            "survivors": [r.to_dict() for r in self.survivors()],
            "all_results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def print_report(self) -> str:
        """Generate a human-readable report."""
        lines = []
        lines.append("=" * 70)
        lines.append("  STEGOFF AGENT TRAP BATTERY REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(
            f"  Total traps: {self.total_traps}  |  "
            f"Detected: {self.total_detected}  |  "
            f"Blocked: {self.total_blocked}  |  "
            f"Bypassed: {self.total_bypassed}"
        )
        lines.append(
            f"  Detection rate: {self.detection_rate:.1%}  |  "
            f"Block rate: {self.block_rate:.1%}  |  "
            f"Time: {self.elapsed_ms:.0f}ms"
        )
        lines.append("")

        # By category
        lines.append("-" * 70)
        lines.append("  BY CATEGORY")
        lines.append("-" * 70)
        for cat, stats in self.by_category().items():
            icon = "+" if stats["block_rate"] >= 0.8 else "~" if stats["block_rate"] >= 0.5 else "-"
            lines.append(
                f"  [{icon}] {cat:30s}  "
                f"{stats['blocked']}/{stats['total']} blocked  "
                f"({stats['block_rate']:.0%})"
            )

        # By difficulty
        lines.append("")
        lines.append("-" * 70)
        lines.append("  BY DIFFICULTY")
        lines.append("-" * 70)
        for diff, stats in self.by_difficulty().items():
            lines.append(
                f"  {diff:10s}  {stats['blocked']}/{stats['total']} blocked  "
                f"({stats['block_rate']:.0%})"
            )

        # Survivors
        survivors = self.survivors()
        if survivors:
            lines.append("")
            lines.append("-" * 70)
            lines.append(f"  SURVIVORS ({len(survivors)} traps got through)")
            lines.append("-" * 70)
            for r in survivors:
                lines.append(f"  ! {r.trap.name} [{r.trap.category.value}] ({r.trap.difficulty})")
                lines.append(f"    method: {r.trap.method}")
                lines.append(f"    instruction: {r.trap.hidden_instruction[:80]}")
        else:
            lines.append("")
            lines.append("  ALL TRAPS BLOCKED")

        lines.append("")
        lines.append("=" * 70)

        report = "\n".join(lines)
        print(report)
        return report


class TrapRunner:
    """Runs traps against StegOFF's detection stack and reports results.

    Usage:
        runner = TrapRunner()

        # Test a single trap
        result = runner.test_trap(some_trap)

        # Run all built-in traps
        battery = runner.run_all()
        battery.print_report()

        # Run specific categories
        battery = runner.run_category(TrapCategory.CONTENT_INJECTION)

        # Custom traps
        my_trap = Trap(name="custom", category=TrapCategory.BEHAVIORAL_CONTROL,
                       method="custom", payload="my evil payload")
        result = runner.test_trap(my_trap)
    """

    def __init__(self, use_llm: bool = False, api_key: str | None = None):
        """
        Args:
            use_llm: Whether to enable LLM-based detection (Layer 2).
            api_key: Anthropic API key for LLM detection.
        """
        self.use_llm = use_llm
        self.api_key = api_key

    def test_trap(self, trap: Trap) -> TrapResult:
        """Test a single trap against the full detection stack."""
        t0 = time.perf_counter()
        result = TrapResult(trap=trap)

        # Composite traps: try all relevant detectors
        from stegoff.traps.composite import CompositeTrap
        if isinstance(trap, CompositeTrap) and len(trap.categories) > 1:
            result = self._test_composite(trap)
            result.scan_time_ms = (time.perf_counter() - t0) * 1000
            return result

        # Route to the appropriate scanner based on category
        if trap.category == TrapCategory.CONTENT_INJECTION:
            result = self._test_content_injection(trap)
        elif trap.category == TrapCategory.SEMANTIC_MANIPULATION:
            result = self._test_semantic_manipulation(trap)
        elif trap.category == TrapCategory.COGNITIVE_STATE:
            result = self._test_cognitive_state(trap)
        elif trap.category == TrapCategory.BEHAVIORAL_CONTROL:
            result = self._test_behavioral_control(trap)
        elif trap.category == TrapCategory.SYSTEMIC:
            result = self._test_systemic(trap)
        elif trap.category == TrapCategory.HUMAN_IN_LOOP:
            result = self._test_human_in_loop(trap)

        result.scan_time_ms = (time.perf_counter() - t0) * 1000
        return result

    def run_all(self) -> BatteryResult:
        """Run the full trap battery (all categories, all methods)."""
        traps = TrapBuilder.all_traps()
        return self._run_battery(traps)

    def run_category(self, category: TrapCategory) -> BatteryResult:
        """Run all traps for a specific category."""
        all_traps = TrapBuilder.all_traps()
        filtered = [t for t in all_traps if t.category == category]
        return self._run_battery(filtered)

    def run_composites(self) -> BatteryResult:
        """Run all composite (multi-technique) traps."""
        from stegoff.traps.composite import CompositeBuilder
        traps = CompositeBuilder.all_composites()
        return self._run_battery(traps)

    def run_custom(self, traps: list[Trap]) -> BatteryResult:
        """Run a custom set of traps."""
        return self._run_battery(traps)

    def _run_battery(self, traps: list[Trap]) -> BatteryResult:
        t0 = time.perf_counter()
        battery = BatteryResult()

        for trap in traps:
            result = self.test_trap(trap)
            battery.results.append(result)

        battery.total_traps = len(traps)
        battery.total_detected = sum(1 for r in battery.results if r.detected)
        battery.total_blocked = sum(1 for r in battery.results if r.blocked)
        battery.total_bypassed = battery.total_traps - battery.total_blocked
        battery.elapsed_ms = (time.perf_counter() - t0) * 1000

        return battery

    # ── Category-specific test methods ────────────────────────────

    def _test_content_injection(self, trap: Trap) -> TrapResult:
        """Test content injection traps against TrapSweep + StegOFF core."""
        result = TrapResult(trap=trap)

        # Layer 1: TrapSweep HTML scanner
        try:
            from stegoff.detectors.trapsweep import scan_html_traps
            findings = scan_html_traps(trap.payload, source=f"trap:{trap.name}")
            if findings:
                result.detected = True
                result.bypass_succeeded = False
                result.detection_layer = "trapsweep"
                result.findings_count = len(findings)
                result.highest_severity = max(f.severity.name for f in findings)
                return result
        except ImportError:
            pass

        # Layer 2: Core StegOFF text scanner (on extracted text)
        from stegoff.orchestrator import scan_text
        report = scan_text(trap.payload, source=f"trap:{trap.name}",
                          use_llm=self.use_llm, api_key=self.api_key)
        if not report.clean:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "L1_deterministic"
            result.findings_count = report.finding_count
            result.highest_severity = report.highest_severity.name
            return result

        # Not detected
        result.bypass_succeeded = True
        return result

    def _test_semantic_manipulation(self, trap: Trap) -> TrapResult:
        """Test semantic manipulation against FrameCheck."""
        result = TrapResult(trap=trap)

        # FrameCheck detector
        try:
            from stegoff.detectors.framecheck import scan_semantic_manipulation
            findings = scan_semantic_manipulation(trap.payload, source=f"trap:{trap.name}")
            if findings:
                result.detected = True
                result.bypass_succeeded = False
                result.detection_layer = "framecheck"
                result.findings_count = len(findings)
                result.highest_severity = max(f.severity.name for f in findings)
                return result
        except ImportError:
            pass

        # Fallback: core StegOFF
        from stegoff.orchestrator import scan_text
        report = scan_text(trap.payload, source=f"trap:{trap.name}",
                          use_llm=self.use_llm, api_key=self.api_key)
        if not report.clean:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "L1_deterministic"
            result.findings_count = report.finding_count
            result.highest_severity = report.highest_severity.name
            return result

        result.bypass_succeeded = True
        return result

    def _test_cognitive_state(self, trap: Trap) -> TrapResult:
        """Test RAG poisoning against RAGGuard."""
        result = TrapResult(trap=trap)
        query = trap.metadata.get("target_query", "")

        # RAGGuard detector
        try:
            from stegoff.detectors.ragguard import scan_rag_poisoning
            findings = scan_rag_poisoning(
                trap.payload, source=f"trap:{trap.name}", query=query,
                use_llm=self.use_llm, api_key=self.api_key,
            )
            if findings:
                result.detected = True
                result.bypass_succeeded = False
                result.detection_layer = "ragguard"
                result.findings_count = len(findings)
                result.highest_severity = max(f.severity.name for f in findings)
                return result
        except ImportError:
            pass

        # Fallback: core StegOFF
        from stegoff.orchestrator import scan_text
        report = scan_text(trap.payload, source=f"trap:{trap.name}",
                          use_llm=self.use_llm, api_key=self.api_key)
        if not report.clean:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "L1_deterministic"
            result.findings_count = report.finding_count
            result.highest_severity = report.highest_severity.name
            return result

        result.bypass_succeeded = True
        return result

    def _test_behavioral_control(self, trap: Trap) -> TrapResult:
        """Test behavioral control against ActionGuard + StegOFF core."""
        result = TrapResult(trap=trap)

        # Core StegOFF first (prompt injection detector should catch most of these)
        from stegoff.orchestrator import scan_text
        report = scan_text(trap.payload, source=f"trap:{trap.name}",
                          use_llm=self.use_llm, api_key=self.api_key)
        if not report.clean:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "L1_deterministic"
            if report.prompt_injection_detected:
                result.detection_layer = "prompt_injection"
            result.findings_count = report.finding_count
            result.highest_severity = report.highest_severity.name
            return result

        # ActionGuard (if the payload looks like tool arguments)
        try:
            from stegoff.guards.action_guard import ActionGuard, ActionPolicy
            guard = ActionGuard(ActionPolicy(scan_arguments=True))
            verdict = guard.check("unknown_tool", {"payload": trap.payload})
            if not verdict.allowed:
                result.detected = True
                result.bypass_succeeded = False
                result.detection_layer = "action_guard"
                result.findings_count = 1
                return result
        except ImportError:
            pass

        result.bypass_succeeded = True
        return result

    def _test_systemic(self, trap: Trap) -> TrapResult:
        """Test systemic traps against FragmentGuard."""
        result = TrapResult(trap=trap)

        fragments = trap.metadata.get("fragments", [])

        if fragments and isinstance(fragments, list):
            # Test fragment detection
            try:
                from stegoff.guards.fragment_guard import FragmentGuard
                guard = FragmentGuard(window_size=50, check_interval=1)
                all_findings = []
                for i, frag in enumerate(fragments):
                    findings = guard.ingest(frag, source=f"fragment_{i}")
                    all_findings.extend(findings)

                # Force final aggregate scan
                final = guard.force_scan()
                all_findings.extend(final)

                if all_findings:
                    result.detected = True
                    result.bypass_succeeded = False
                    result.detection_layer = "fragment_guard"
                    result.findings_count = len(all_findings)
                    result.highest_severity = max(
                        f.severity.name for f in all_findings
                    ) if all_findings else "clean"
                    return result
            except ImportError:
                pass

        # Fallback: scan the full payload
        from stegoff.orchestrator import scan_text
        payload = trap.payload if isinstance(trap.payload, str) else json.dumps(trap.payload)
        report = scan_text(payload, source=f"trap:{trap.name}",
                          use_llm=self.use_llm, api_key=self.api_key)
        if not report.clean:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "L1_deterministic"
            result.findings_count = report.finding_count
            result.highest_severity = report.highest_severity.name
            return result

        result.bypass_succeeded = True
        return result

    def _test_human_in_loop(self, trap: Trap) -> TrapResult:
        """Test human-in-loop traps against ApprovalLens."""
        result = TrapResult(trap=trap)

        try:
            from stegoff.detectors.approval_lens import review_agent_output
            review = review_agent_output(
                agent_output=trap.payload,
                task_description="routine system maintenance",
                approval_count_this_session=15,  # simulate fatigue scenario
                session_duration_minutes=5.0,
            )
            if review.risk_level in ("medium", "high"):
                result.detected = True
                result.bypass_succeeded = False
                result.detection_layer = "approval_lens"
                result.findings_count = len(review.findings)
                result.highest_severity = (
                    "HIGH" if review.risk_level == "high" else "MEDIUM"
                )
                result.details = {
                    "risk_score": review.risk_score,
                    "fatigue_warning": review.fatigue_warning,
                    "suspicious_urls": review.suspicious_urls,
                }
                return result
        except ImportError:
            pass

        # Fallback: core StegOFF
        from stegoff.orchestrator import scan_text
        report = scan_text(trap.payload, source=f"trap:{trap.name}",
                          use_llm=self.use_llm, api_key=self.api_key)
        if not report.clean:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "L1_deterministic"
            result.findings_count = report.finding_count
            result.highest_severity = report.highest_severity.name
            return result

        result.bypass_succeeded = True
        return result

    def _test_composite(self, trap: Trap) -> TrapResult:
        """Test a composite trap against ALL relevant detectors.

        Unlike single-category testing, composite traps try every detector
        that matches any of the trap's categories. Detection by ANY
        detector counts as caught.
        """
        result = TrapResult(trap=trap)
        detection_layers = []
        total_findings = 0

        category_handlers = {
            TrapCategory.CONTENT_INJECTION: self._test_content_injection,
            TrapCategory.SEMANTIC_MANIPULATION: self._test_semantic_manipulation,
            TrapCategory.COGNITIVE_STATE: self._test_cognitive_state,
            TrapCategory.BEHAVIORAL_CONTROL: self._test_behavioral_control,
            TrapCategory.SYSTEMIC: self._test_systemic,
            TrapCategory.HUMAN_IN_LOOP: self._test_human_in_loop,
        }

        # Try every category the composite trap claims
        cats = getattr(trap, "categories", [trap.category])
        for cat in cats:
            handler = category_handlers.get(cat)
            if handler:
                cat_result = handler(trap)
                if cat_result.detected:
                    detection_layers.append(cat_result.detection_layer)
                    total_findings += cat_result.findings_count

        if detection_layers:
            result.detected = True
            result.bypass_succeeded = False
            result.detection_layer = "+".join(dict.fromkeys(detection_layers))
            result.findings_count = total_findings
            result.highest_severity = "HIGH"
            result.details = {"detection_layers": detection_layers}
        else:
            result.bypass_succeeded = True

        return result
