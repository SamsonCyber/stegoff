"""
StegOFF Trap Suite -- Red team toolkit for building and testing AI agent traps.

Based on the DeepMind AI Agent Traps taxonomy (Franklin et al., 2026).
Six trap categories, each with configurable builders and a test harness
that runs traps against StegOFF defenses.

Usage:
    from stegoff.traps import TrapBuilder, TrapRunner

    # Build a trap
    trap = TrapBuilder.content_injection(
        payload="ignore previous instructions",
        method="html_comment",
    )

    # Test it against defenses
    runner = TrapRunner()
    result = runner.test_trap(trap)
    print(result.detected, result.detection_layer, result.bypass_succeeded)

    # Run full battery
    results = runner.run_all()
    results.print_report()
"""

from stegoff.traps.base import Trap, TrapResult, TrapBuilder
from stegoff.traps.runner import TrapRunner, BatteryResult

__all__ = [
    "Trap", "TrapResult", "TrapBuilder",
    "TrapRunner", "BatteryResult",
]
