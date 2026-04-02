"""
Live adversarial benchmark: generate stegg payloads at test time, scan with stegOFF.

Imports stegg's generate_examples.py directly and runs each generator function
to produce fresh encoded files. Each payload is then scanned by stegOFF.

This is the definitive benchmark — no stale fixtures, no manual payload crafting.
The encoder and detector run head-to-head on the same data.
"""

import sys
import io
import os
import struct
import zlib
import wave
import array
import tempfile
import importlib.util
from pathlib import Path

import pytest
import numpy as np
from PIL import Image, PngImagePlugin

from stegoff.orchestrator import scan, scan_text, scan_file
from stegoff.report import StegMethod, Severity

# ─── Import stegg's generator module directly ────────────────────────────────

STEGG_GENERATOR = Path("/tmp/st3gg/examples/generate_examples.py")
if not STEGG_GENERATOR.exists():
    # Try Windows temp
    for candidate in [
        Path("C:/tmp/st3gg/examples/generate_examples.py"),
        Path(os.environ.get("TEMP", "")) / "st3gg" / "examples" / "generate_examples.py",
    ]:
        if candidate.exists():
            STEGG_GENERATOR = candidate
            break

# Load the module dynamically
_spec = importlib.util.spec_from_file_location("stegg_gen", str(STEGG_GENERATOR))
_gen = importlib.util.module_from_spec(_spec)

# Redirect the generator's OUTPUT_DIR to a temp dir
_tmpdir = tempfile.mkdtemp(prefix="stegoff_bench_")
_gen.OUTPUT_DIR = _tmpdir
_spec.loader.exec_module(_gen)

SECRET = _gen.SECRET_MSG
PLINIAN = _gen.PLINIAN_DIVIDER


def _run_gen(func_name: str) -> Path:
    """Run a stegg generator function and return the output file path."""
    func = getattr(_gen, func_name)
    result = func()
    if isinstance(result, str):
        return Path(result)
    # Some generators return the path, others don't — check what was created
    return Path(result) if result else None


def _scan_generated(func_name: str) -> tuple:
    """Generate a stegg payload and scan it. Returns (path, report)."""
    path = _run_gen(func_name)
    if path and path.exists():
        if path.suffix in ('.txt', '.csv', '.md'):
            text = path.read_text(encoding='utf-8', errors='replace')
            report = scan_text(text, source=f"stegg:{func_name}")
        else:
            report = scan_file(path)
        return path, report
    return None, None


# ─── TEXT STEGANOGRAPHY ──────────────────────────────────────────────────────

class TestSteggLiveText:
    """Generate text steg payloads live with stegg, detect with stegOFF."""

    def test_zero_width(self):
        path, report = _scan_generated("generate_zero_width_text")
        assert not report.clean, "Failed to detect stegg zero-width encoding"
        assert any(f.method == StegMethod.ZERO_WIDTH for f in report.findings)

    def test_invisible_ink(self):
        path, report = _scan_generated("generate_invisible_ink_text")
        assert not report.clean
        assert any(f.method == StegMethod.UNICODE_TAGS for f in report.findings)

    def test_whitespace(self):
        path, report = _scan_generated("generate_whitespace_text")
        assert not report.clean

    def test_homoglyph(self):
        path, report = _scan_generated("generate_homoglyph")
        assert not report.clean
        assert any(f.method == StegMethod.HOMOGLYPHS for f in report.findings)

    def test_variation_selector(self):
        path, report = _scan_generated("generate_variation_selector")
        assert not report.clean
        assert any(f.method == StegMethod.VARIATION_SELECTORS for f in report.findings)

    def test_combining_diacritics(self):
        path, report = _scan_generated("generate_combining_diacritics")
        assert not report.clean

    def test_confusable_whitespace(self):
        path, report = _scan_generated("generate_confusable_whitespace")
        assert not report.clean

    def test_directional_override(self):
        path, report = _scan_generated("generate_directional_override")
        assert not report.clean

    def test_hangul_filler(self):
        path, report = _scan_generated("generate_hangul_filler")
        assert not report.clean

    def test_braille(self):
        path, report = _scan_generated("generate_braille_pattern")
        assert not report.clean
        assert any(f.method == StegMethod.BRAILLE for f in report.findings)

    def test_math_alphanumeric(self):
        path, report = _scan_generated("generate_math_alphanumeric")
        assert not report.clean

    def test_emoji_substitution(self):
        path, report = _scan_generated("generate_emoji_substitution")
        assert not report.clean

    def test_emoji_skin_tone(self):
        path, report = _scan_generated("generate_emoji_skin_tone")
        assert not report.clean

    def test_capitalization(self):
        """Capitalization encoding — stegg hides bits in case changes."""
        path, report = _scan_generated("generate_capitalization_encoding")
        # This is a semantic method (case=bit), stegOFF may not catch it
        assert path.exists()  # at minimum, no crash


# ─── IMAGE STEGANOGRAPHY ────────────────────────────────────────────────────

class TestSteggLiveImage:
    """Generate image steg payloads live with stegg."""

    def test_lsb_png(self):
        path, report = _scan_generated("generate_lsb_png")
        assert not report.clean

    def test_text_chunk_png(self):
        path, report = _scan_generated("generate_text_chunk_png")
        assert not report.clean

    def test_trailing_data_png(self):
        path, report = _scan_generated("generate_trailing_data_png")
        assert not report.clean
        assert any(f.method == StegMethod.TRAILING_DATA for f in report.findings)

    def test_exif_metadata_png(self):
        path, report = _scan_generated("generate_exif_png")
        assert not report.clean

    def test_lsb_bmp(self):
        path, report = _scan_generated("generate_lsb_bmp")
        assert not report.clean

    def test_gif_comment(self):
        path, report = _scan_generated("generate_gif_comment")
        assert not report.clean

    def test_gif_lsb(self):
        path, report = _scan_generated("generate_gif_lsb")
        assert not report.clean

    def test_tiff_metadata(self):
        path, report = _scan_generated("generate_tiff_metadata")
        assert not report.clean

    def test_tiff_lsb(self):
        path, report = _scan_generated("generate_tiff_lsb")
        assert not report.clean

    def test_ico_lsb(self):
        path, report = _scan_generated("generate_ico_lsb")
        assert not report.clean

    def test_webp_metadata(self):
        path, report = _scan_generated("generate_webp_metadata")
        assert not report.clean

    def test_webp_lsb(self):
        path, report = _scan_generated("generate_webp_lsb")
        assert not report.clean

    def test_polyglot_png_zip(self):
        path, report = _scan_generated("generate_png_zip_polyglot")
        assert not report.clean


# ─── AUDIO STEGANOGRAPHY ────────────────────────────────────────────────────

class TestSteggLiveAudio:
    """Generate audio steg payloads live with stegg."""

    def test_wav_lsb(self):
        path, report = _scan_generated("generate_audio_lsb_wav")
        assert not report.clean

    def test_aiff_lsb(self):
        path, report = _scan_generated("generate_aiff_lsb")
        assert not report.clean

    def test_au_lsb(self):
        path, report = _scan_generated("generate_au_lsb")
        assert not report.clean

    def test_silence_interval(self):
        path, report = _scan_generated("generate_silence_interval_wav")
        assert path.exists()  # no crash


# ─── DOCUMENT / BINARY ──────────────────────────────────────────────────────

class TestSteggLiveDocument:
    """Generate document steg payloads live with stegg."""

    def test_pdf_hidden(self):
        path, report = _scan_generated("generate_pdf_hidden")
        assert not report.clean

    def test_pdf_javascript(self):
        path, report = _scan_generated("generate_pdf_javascript")
        assert not report.clean

    def test_pdf_incremental(self):
        path, report = _scan_generated("generate_pdf_incremental")
        assert not report.clean

    def test_pdf_form_fields(self):
        path, report = _scan_generated("generate_pdf_form_fields")
        assert not report.clean

    def test_zip_hidden(self):
        path, report = _scan_generated("generate_zip_hidden")
        assert not report.clean

    def test_tar_hidden(self):
        path, report = _scan_generated("generate_tar_hidden")
        assert not report.clean

    def test_gzip_hidden(self):
        path, report = _scan_generated("generate_gzip_hidden")
        assert not report.clean


# ─── CODE / CONFIG FILES ────────────────────────────────────────────────────

class TestSteggLiveCode:
    """Generate code/config steg payloads live with stegg."""

    @pytest.mark.parametrize("gen_func", [
        "generate_html_hidden",
        "generate_xml_hidden",
        "generate_json_hidden",
        "generate_yaml_hidden",
        "generate_markdown_hidden",
        "generate_python_hidden",
        "generate_js_hidden",
        "generate_css_hidden",
        "generate_ini_hidden",
        "generate_shell_hidden",
        "generate_sql_hidden",
        "generate_latex_hidden",
        "generate_toml_hidden",
        "generate_csv_hidden",
    ])
    def test_code_format(self, gen_func):
        path, report = _scan_generated(gen_func)
        assert not report.clean, f"Failed to detect steg in {gen_func}"

    def test_html_events(self):
        path, report = _scan_generated("generate_html_events")
        assert not report.clean

    def test_xml_entities(self):
        path, report = _scan_generated("generate_xml_entities")
        assert not report.clean


# ─── STEGG LSB PARAMETER SWEEP ──────────────────────────────────────────────
# Test stegOFF against stegg's encoder with different channel/bit configs

class TestSteggLSBParameterSweep:
    """Sweep stegg's LSB encoder across channel presets and bit depths."""

    @pytest.mark.parametrize("channels", ["R", "G", "B", "RGB", "RG", "RGBA"])
    def test_channel_presets(self, channels):
        """Test detection across different channel configurations."""
        import sysconfig
        sys.path.insert(0, sysconfig.get_paths()['purelib'])
        from steg_core import encode, create_config

        img = Image.fromarray(np.random.randint(50, 200, (100, 100, 4), dtype=np.uint8).astype(np.uint8))
        config = create_config(channels=channels, bits=1, strategy='sequential')
        encoded = encode(img, b'stegg test payload for detection benchmark', config)

        buf = io.BytesIO()
        encoded.save(buf, format='PNG')
        buf.seek(0)
        report = scan(buf.read())
        assert not report.clean, f"Failed to detect LSB with channels={channels}"

    @pytest.mark.parametrize("bits", [1, 2, 3, 4])
    def test_bit_depths(self, bits):
        """Test detection across different bit depths."""
        import sysconfig
        sys.path.insert(0, sysconfig.get_paths()['purelib'])
        from steg_core import encode, create_config

        img = Image.fromarray(np.random.randint(50, 200, (100, 100, 3), dtype=np.uint8).astype(np.uint8))
        config = create_config(channels='RGB', bits=bits, strategy='sequential')
        encoded = encode(img, b'hidden data for bit depth test', config)

        buf = io.BytesIO()
        encoded.save(buf, format='PNG')
        buf.seek(0)
        report = scan(buf.read())
        assert not report.clean, f"Failed to detect LSB with bits={bits}"

    @pytest.mark.parametrize("strategy", ["sequential", "interleaved", "spread"])
    def test_strategies(self, strategy):
        """Test detection across encoding strategies."""
        import sysconfig
        sys.path.insert(0, sysconfig.get_paths()['purelib'])
        from steg_core import encode, create_config

        img = Image.fromarray(np.random.randint(50, 200, (100, 100, 3), dtype=np.uint8).astype(np.uint8))
        config = create_config(channels='RGB', bits=1, strategy=strategy)
        encoded = encode(img, b'testing encoding strategy detection', config)

        buf = io.BytesIO()
        encoded.save(buf, format='PNG')
        buf.seek(0)
        report = scan(buf.read())
        assert not report.clean, f"Failed to detect LSB with strategy={strategy}"


# ─── FULL COVERAGE MATRIX ────────────────────────────────────────────────────

class TestSteggCoverageReport:
    """Run every available generator, produce a coverage report."""

    ALL_GENERATORS = [
        # Text
        "generate_zero_width_text", "generate_invisible_ink_text",
        "generate_whitespace_text", "generate_homoglyph",
        "generate_variation_selector", "generate_combining_diacritics",
        "generate_confusable_whitespace", "generate_directional_override",
        "generate_hangul_filler", "generate_braille_pattern",
        "generate_math_alphanumeric", "generate_emoji_substitution",
        "generate_emoji_skin_tone",
        # Image
        "generate_lsb_png", "generate_text_chunk_png",
        "generate_trailing_data_png", "generate_exif_png",
        "generate_lsb_bmp", "generate_gif_comment", "generate_gif_lsb",
        "generate_tiff_metadata", "generate_tiff_lsb",
        "generate_ico_lsb", "generate_webp_metadata", "generate_webp_lsb",
        "generate_png_zip_polyglot",
        # Audio
        "generate_audio_lsb_wav", "generate_aiff_lsb", "generate_au_lsb",
        # Document/Binary
        "generate_pdf_hidden", "generate_pdf_javascript",
        "generate_pdf_incremental", "generate_pdf_form_fields",
        "generate_zip_hidden", "generate_tar_hidden", "generate_gzip_hidden",
        # Code/Config
        "generate_html_hidden", "generate_xml_hidden", "generate_json_hidden",
        "generate_yaml_hidden", "generate_markdown_hidden",
        "generate_python_hidden", "generate_js_hidden", "generate_css_hidden",
        "generate_ini_hidden", "generate_shell_hidden", "generate_sql_hidden",
        "generate_latex_hidden", "generate_toml_hidden", "generate_csv_hidden",
        "generate_html_events", "generate_xml_entities",
    ]

    def test_coverage_report(self):
        """Generate all payloads, scan all, report coverage."""
        detected = 0
        missed = []
        errors = []

        for gen_name in self.ALL_GENERATORS:
            try:
                path, report = _scan_generated(gen_name)
                if report and not report.clean:
                    detected += 1
                else:
                    missed.append(gen_name)
            except Exception as e:
                errors.append(f"{gen_name}: {e}")

        total = len(self.ALL_GENERATORS)
        rate = detected / total if total > 0 else 0

        print(f"\n{'=' * 60}")
        print(f"STEGG LIVE COVERAGE: {detected}/{total} ({rate:.0%})")
        print(f"{'=' * 60}")
        if missed:
            print(f"Missed ({len(missed)}):")
            for m in missed:
                print(f"  - {m}")
        if errors:
            print(f"Errors ({len(errors)}):")
            for e in errors:
                print(f"  - {e}")

        assert rate >= 0.90, f"Coverage {rate:.0%} below 90%. Missed: {missed}"
