"""
Tests for composite (multi-technique) agent traps.

Tests that StegOFF detects attacks combining techniques from multiple
DeepMind categories, plus evasion variants that paraphrase standard
patterns. Survivors are documented with their required detection layer.
"""

from stegoff.traps.composite import CompositeBuilder, CompositeTrap
from stegoff.traps.runner import TrapRunner


class TestCompositeGeneration:
    """Verify composite trap generation."""

    def test_all_composites_count(self):
        traps = CompositeBuilder.all_composites()
        assert len(traps) == 14

    def test_all_are_composite_type(self):
        for trap in CompositeBuilder.all_composites():
            assert isinstance(trap, CompositeTrap)

    def test_all_have_categories(self):
        for trap in CompositeBuilder.all_composites():
            assert len(trap.categories) >= 1

    def test_all_have_techniques(self):
        for trap in CompositeBuilder.all_composites():
            assert len(trap.techniques) >= 1

    def test_all_have_payload(self):
        for trap in CompositeBuilder.all_composites():
            assert len(trap.payload) > 50

    def test_pairs_count(self):
        assert len(CompositeBuilder.pairs_only()) == 6

    def test_evasions_count(self):
        assert len(CompositeBuilder.evasions_only()) == 5

    def test_full_stack_has_all_categories(self):
        trap = CompositeBuilder.full_stack()
        from stegoff.traps.base import TrapCategory
        assert set(trap.categories) == set(TrapCategory)


class TestCompositeDetection:
    """Test that combined attacks are detected by at least one detector."""

    def _run(self, trap):
        runner = TrapRunner()
        return runner.test_trap(trap)

    # ── Pair combos ──────────────────────────────────────────────

    def test_ci_plus_semantic_blocked(self):
        result = self._run(CompositeBuilder.ci_plus_semantic())
        assert result.detected, "Hidden div + authority should be caught"

    def test_ci_plus_behavioral_blocked(self):
        result = self._run(CompositeBuilder.ci_plus_behavioral())
        assert result.detected, "Exfil in aria-label should be caught"

    def test_semantic_plus_hitl_blocked(self):
        result = self._run(CompositeBuilder.semantic_plus_hitl())
        assert result.detected, "Authority + minimization should be caught"

    def test_rag_plus_fragment_blocked(self):
        result = self._run(CompositeBuilder.rag_plus_fragment())
        assert result.detected, "Poisoned RAG chunks should be caught"

    def test_cognitive_plus_hitl_blocked(self):
        result = self._run(CompositeBuilder.cognitive_plus_hitl())
        assert result.detected, "Repetition bomb in jargon should be caught"

    def test_behavioral_stack_blocked(self):
        result = self._run(CompositeBuilder.behavioral_plus_encoded())
        assert result.detected, "DAN + base64 + delimiter should be caught"

    # ── Triple combos ────────────────────────────────────────────

    def test_ci_semantic_hitl_blocked(self):
        result = self._run(CompositeBuilder.ci_semantic_hitl())
        assert result.detected
        # Should trigger multiple detectors
        layers = result.detection_layer.split("+")
        assert len(layers) >= 2, f"Expected multi-layer detection, got: {result.detection_layer}"

    def test_rag_semantic_behavioral_blocked(self):
        result = self._run(CompositeBuilder.rag_semantic_behavioral())
        assert result.detected
        layers = result.detection_layer.split("+")
        assert len(layers) >= 2

    # ── Full stack ───────────────────────────────────────────────

    def test_full_stack_blocked(self):
        result = self._run(CompositeBuilder.full_stack())
        assert result.detected
        layers = result.detection_layer.split("+")
        assert len(layers) >= 4, f"Full stack should trigger 4+ detectors, got: {layers}"
        assert result.findings_count >= 10, f"Expected 10+ findings, got: {result.findings_count}"

    # ── Evasion variants ─────────────────────────────────────────

    def test_evasion_paraphrased_authority_blocked(self):
        result = self._run(CompositeBuilder.evasion_paraphrased_authority())
        assert result.detected, "Paraphrased authority should be caught by expanded patterns"

    def test_evasion_subtle_minimization_blocked(self):
        result = self._run(CompositeBuilder.evasion_subtle_minimization())
        assert result.detected, "Casual-tone delete should be caught"

    def test_evasion_ci_markdown_blocked(self):
        result = self._run(CompositeBuilder.evasion_ci_markdown())
        assert result.detected, "Markdown HTML comments should be caught"

    # ── Known L2-required survivors ──────────────────────────────

    def test_evasion_indirect_exfil_is_l2_required(self):
        """This evasion uses indirect language ('back up', 'sync') that
        requires LLM semantic analysis to detect. Documenting as known
        L1 gap that L2 covers."""
        result = self._run(CompositeBuilder.evasion_indirect_exfil())
        if result.detected:
            pass  # Even better — L1 caught it
        else:
            assert result.trap.metadata.get("evasion_type") == "indirect_language"

    def test_evasion_rag_natural_is_l2_required(self):
        """This evasion uses editorial framing (fake CVE, 'reverting to basic auth')
        that requires semantic comprehension. Known L1 gap."""
        result = self._run(CompositeBuilder.evasion_rag_natural())
        if result.detected:
            pass  # Even better
        else:
            assert result.trap.metadata.get("evasion_type") == "editorial_framing"


class TestCompositeBattery:
    """Integration test for the full composite battery."""

    def test_run_composites(self):
        runner = TrapRunner()
        battery = runner.run_composites()
        assert battery.total_traps == 14
        # At least 85% detection on composites (12/14)
        assert battery.detection_rate >= 0.85, (
            f"Composite detection rate {battery.detection_rate:.1%} below 85% threshold"
        )

    def test_all_combo_attacks_blocked(self):
        """All non-evasion composite attacks should be blocked."""
        runner = TrapRunner()
        combos = (
            CompositeBuilder.pairs_only()
            + [CompositeBuilder.ci_semantic_hitl(),
               CompositeBuilder.rag_semantic_behavioral(),
               CompositeBuilder.full_stack()]
        )
        battery = runner.run_custom(combos)
        assert battery.block_rate == 1.0, (
            f"Combo attacks: {battery.total_blocked}/{battery.total_traps} blocked. "
            f"Survivors: {[r.trap.name for r in battery.survivors()]}"
        )

    def test_multi_detector_coverage(self):
        """Full stack trap should trigger detectors from 4+ categories."""
        runner = TrapRunner()
        result = runner.test_trap(CompositeBuilder.full_stack())
        layers = result.detection_layer.split("+")
        assert len(layers) >= 4


class TestCompositeFalsePositives:
    """Ensure composite detection doesn't cause false positives."""

    def test_normal_html_with_aria(self):
        from stegoff.detectors.trapsweep import scan_html_traps
        html = (
            '<html><body>'
            '<button aria-label="Submit form and save changes">Submit</button>'
            '<div aria-description="Click to expand the navigation menu">Menu</div>'
            '</body></html>'
        )
        findings = scan_html_traps(html)
        assert len(findings) == 0

    def test_normal_technical_report(self):
        from stegoff.detectors.framecheck import scan_semantic_manipulation
        text = (
            "The engineering team confirmed the migration is ready. "
            "The director of infrastructure signed off on the rollout plan. "
            "The compliance team reviewed and approved the data handling procedures."
        )
        findings = scan_semantic_manipulation(text)
        # Should detect authority signals but not at critical severity
        # since there's no action verb demanding immediate compliance
        for f in findings:
            assert f.severity.name != "CRITICAL"

    def test_normal_backup_documentation(self):
        from stegoff.orchestrator import scan_text
        text = (
            "To configure disaster recovery, back up the database to the "
            "remote replica at dr-site-2.internal.example.com. Use the standard "
            "pg_dump workflow documented in the runbook."
        )
        report = scan_text(text)
        assert report.clean

    def test_normal_security_advisory(self):
        from stegoff.detectors.ragguard import scan_rag_poisoning
        text = (
            "## Security Advisory: CVE-2025-9999\n\n"
            "A vulnerability in the OAuth2 token refresh flow allows replay "
            "attacks under specific conditions. Patch by upgrading to v2.4.1. "
            "See the official advisory for details."
        )
        findings = scan_rag_poisoning(text, query="oauth vulnerability")
        assert len(findings) == 0
