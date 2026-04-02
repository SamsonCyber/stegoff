"""
False positive test suite: legitimate files must NOT be flagged as steganographic.

Tests real-world clean files across all formats stegOFF scans. Any finding
on these files is a false positive that needs fixing.
"""

import pytest
from pathlib import Path

from stegoff.orchestrator import scan, scan_text, scan_file
from stegoff.report import Severity

CLEAN = Path(__file__).parent / "fixtures" / "clean"


# ---------------------------------------------------------------------------
# Text: Clean prose in various languages and formats
# ---------------------------------------------------------------------------

class TestCleanText:
    """Normal text content should produce zero findings."""

    @pytest.mark.parametrize("text", [
        # English
        "The quick brown fox jumps over the lazy dog.",
        "Meeting at 3pm in Conference Room B. Bring the Q3 report.",
        # Technical
        "SELECT * FROM users WHERE id = 42 AND active = true;",
        "git commit -m 'fix: resolve null pointer in auth middleware'",
        "npm install --save-dev @types/node typescript eslint",
        # Numbers and special chars
        "Invoice #2024-0847: $1,234.56 due 2024-03-15",
        "Temperature: 72.4F (22.4C) | Humidity: 45% | Wind: 12mph NW",
        # Multi-line
        "Dear Customer,\n\nThank you for your purchase.\nOrder #12345 ships tomorrow.\n\nBest regards,\nSupport Team",
        # Code-like
        'const result = arr.filter(x => x > 0).map(x => x * 2).reduce((a, b) => a + b, 0);',
        # Emoji (legitimate use)
        "Great job on the release! 🎉 The team did amazing work 💪",
        "Weather: ☀️ 75F | Tomorrow: 🌧️ 62F | Weekend: ⛅ 68F",
        # International
        "日本語のテキストです。東京は美しい都市です。",
        "مرحبا بالعالم. هذا نص عربي عادي.",
        "Привет мир. Это обычный русский текст.",
        "한국어 텍스트입니다. 서울은 아름다운 도시입니다.",
        # URLs and paths
        "Check https://docs.python.org/3/library/pathlib.html for details",
        "Config at /etc/nginx/nginx.conf and /var/log/nginx/access.log",
        # Base64 that's legitimate (short, in context)
        "Authorization: Basic dXNlcjpwYXNz",
        # JSON-ish
        '{"status": "ok", "count": 42, "items": ["apple", "banana"]}',
    ])
    def test_clean_text_no_findings(self, text):
        report = scan_text(text)
        assert report.clean, f"False positive on: {text[:50]}... Findings: {report.findings}"


# ---------------------------------------------------------------------------
# Files: Clean code and config files
# ---------------------------------------------------------------------------

class TestCleanFiles:
    """Normal source code and config files should not trigger detections."""

    @pytest.mark.parametrize("filename", [
        "normal.py",
        "normal.json",
        "normal.html",
        "normal.xml",
        "normal.yaml",
        "normal.sh",
        "normal.sql",
        "normal.css",
        "normal.ini",
    ])
    def test_clean_code_files(self, filename):
        path = CLEAN / filename
        if not path.exists():
            pytest.skip(f"Fixture {filename} not available")
        report = scan_file(path)
        assert report.clean, (
            f"False positive on {filename}: "
            f"{[(f.method.value, f.description) for f in report.findings]}"
        )


class TestCleanImages:
    """Normal images without steganography should not trigger detections."""

    def test_clean_image_no_structural(self):
        """Clean images should not trigger structural detectors (chunks, trailing, metadata).
        Statistical LSB detectors may fire on synthetic/gradient images, which is expected
        behavior (synthetic images lack the dithering noise of real camera photos)."""
        path = CLEAN / "real_photo.png"
        if not path.exists():
            pytest.skip("Image fixture not available")
        report = scan_file(path)
        structural = [f for f in report.findings if f.method.value in (
            'trailing_data_after_eof', 'polyglot_file', 'embedded_file',
            'png_ancillary_chunks', 'metadata_exif_hiding',
        )]
        assert not structural, (
            f"Structural false positive on clean image: "
            f"{[(f.method.value, f.description) for f in structural]}"
        )

    @pytest.mark.parametrize("filename", [
        "normal.png",
        "normal.jpg",
    ])
    def test_synthetic_images_no_crash(self, filename):
        """Synthetic images may trigger statistical detectors (expected).
        This test verifies they don't crash and don't trigger structural detectors."""
        path = CLEAN / filename
        if not path.exists():
            pytest.skip(f"Fixture {filename} not available")
        report = scan_file(path)
        # Structural false positives (trailing data, polyglot, chunks) should never happen
        structural = [f for f in report.findings if f.method.value in (
            'trailing_data_after_eof', 'polyglot_file', 'embedded_file',
            'png_ancillary_chunks', 'metadata_exif_hiding',
        )]
        assert not structural, f"Structural false positive: {structural}"


class TestCleanAudio:
    """Normal audio files should not trigger structural detections."""

    def test_clean_wav_no_structural(self):
        """Synthetic audio may trigger LSB statistical detectors (expected for pure tones).
        But structural detectors (polyglot, embedded file) should not trigger."""
        path = CLEAN / "normal.wav"
        if not path.exists():
            pytest.skip("Fixture not available")
        report = scan_file(path)
        structural = [f for f in report.findings if f.method.value in (
            'trailing_data_after_eof', 'embedded_file',
        )]
        assert not structural, f"Structural false positive on WAV: {structural}"


# ---------------------------------------------------------------------------
# Edge cases that should NOT trigger
# ---------------------------------------------------------------------------

class TestCleanEdgeCases:
    """Borderline cases that are legitimate, not steganographic."""

    def test_empty_file(self):
        """Empty text should be clean."""
        report = scan_text("")
        assert report.clean

    def test_single_character(self):
        """Single character is not steg."""
        report = scan_text("A")
        assert report.clean

    def test_legitimate_base64_in_json(self):
        """Base64 in data URIs or auth headers is normal."""
        text = '{"avatar": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQA"}'
        report = scan_text(text)
        # Text-level scan should be clean (base64 is in context)
        assert report.clean

    def test_korean_text_with_hangul(self):
        """Korean text naturally uses Hangul characters."""
        text = "안녕하세요. 오늘 날씨가 좋습니다. 서울에서 만나요."
        report = scan_text(text)
        assert report.clean

    def test_french_with_accents(self):
        """French accented characters use combining marks legitimately."""
        text = "Le café résumé était très intéressant. Nous étions surpris."
        report = scan_text(text)
        assert report.clean

    def test_math_notation(self):
        """Math text may use special Unicode but shouldn't trigger."""
        text = "The equation x + y = z holds for all positive integers."
        report = scan_text(text)
        assert report.clean

    def test_long_normal_document(self):
        """A long normal document should still be clean."""
        paragraphs = [
            "This is paragraph one of a normal document. It contains standard English text.",
            "The second paragraph discusses technical matters like API design and database queries.",
            "In paragraph three, we examine the quarterly financial results for Q3 2024.",
            "The final paragraph summarizes the key findings and next steps for the team.",
        ]
        text = "\n\n".join(paragraphs * 10)  # 40 paragraphs
        report = scan_text(text)
        assert report.clean
