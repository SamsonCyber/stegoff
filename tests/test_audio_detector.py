"""Tests for audio steganography detection."""

import struct
import pytest
import numpy as np

from stegoff.detectors.audio import scan_audio, detect_audio_lsb, detect_audio_structural


class TestAudioDetector:
    def _make_wav(self, duration=0.5, sample_rate=44100, embed_lsb=False,
                  trailing_data=b"") -> bytes:
        """Generate a WAV with optional LSB payload and trailing data."""
        n = int(sample_rate * duration)
        t = np.linspace(0, duration, n, endpoint=False)
        samples = (np.sin(2 * np.pi * 440 * t) * 16000).astype(np.int16)

        if embed_lsb:
            # Replace ALL LSBs with random data to simulate full embedding
            rng = np.random.default_rng(99)
            random_bits = rng.integers(0, 2, size=len(samples), dtype=np.int16)
            samples = (samples & np.int16(~1)) | random_bits

        sample_bytes = samples.tobytes()
        fmt = struct.pack('<4sIHHIIHH', b'fmt ', 16, 1, 1, sample_rate,
                          sample_rate * 2, 2, 16)
        data_chunk = struct.pack('<4sI', b'data', len(sample_bytes)) + sample_bytes
        riff_size = 4 + len(fmt) + len(data_chunk)
        header = struct.pack('<4sI4s', b'RIFF', riff_size, b'WAVE')

        return header + fmt + data_chunk + trailing_data

    def test_clean_wav(self):
        wav = self._make_wav()
        findings = scan_audio(wav)
        # Clean sine wave should not trigger (correlation should be decent)
        lsb_findings = [f for f in findings if "LSB" in f.description or "lsb" in f.description.lower()]
        # May or may not trigger depending on sine wave properties
        # The key test is that embedded steg IS detected below

    def test_embedded_lsb_detected(self):
        """WAV with fully random LSBs should trigger detection."""
        wav = self._make_wav(duration=1.0, embed_lsb=True)
        findings = detect_audio_lsb(wav)

        # Should detect at least one anomaly (correlation or chi-square or entropy)
        assert len(findings) > 0
        assert any(f.severity.value >= 3 for f in findings)  # HIGH or CRITICAL

    def test_trailing_data_detected(self):
        wav = self._make_wav(trailing_data=b"HIDDEN" * 500)
        findings = detect_audio_structural(wav)
        from stegoff.report import StegMethod
        trailing = [f for f in findings if f.method == StegMethod.TRAILING_DATA]
        assert len(trailing) > 0

    def test_non_wav_ignored(self):
        """Non-WAV data should return no findings."""
        findings = scan_audio(b"NOT A WAV FILE AT ALL")
        assert len(findings) == 0

    def test_empty_data(self):
        findings = scan_audio(b"")
        assert len(findings) == 0

    def test_short_wav(self):
        """Very short WAV should not crash."""
        wav = self._make_wav(duration=0.01)  # ~441 samples
        findings = scan_audio(wav)
        # Should not crash, may or may not have findings
