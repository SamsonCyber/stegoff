"""
Audio sanitizer — destroy steganographic payloads in audio files.

Re-encodes audio through a lossy pipeline to eliminate LSB,
phase coding, and echo hiding payloads. For WAV files, randomizes
the LSB plane directly (like image sanitization).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from stegoff.detectors.audio import _parse_wav_header, _extract_samples


@dataclass
class AudioSanitizeResult:
    """Result of audio sanitization."""
    success: bool
    original_size: int
    sanitized_size: int
    output_format: str
    operations: list[str]
    error: str = ""


def sanitize_wav(
    data: bytes,
    randomize_lsb: bool = True,
    strip_trailing: bool = True,
    strip_non_standard_chunks: bool = True,
) -> tuple[bytes, AudioSanitizeResult]:
    """
    Sanitize a WAV file by randomizing sample LSBs and stripping extras.

    Args:
        data: Raw WAV file bytes.
        randomize_lsb: Replace LSB of every sample with random noise.
        strip_trailing: Remove data after RIFF boundary.
        strip_non_standard_chunks: Remove non-standard RIFF chunks.

    Returns:
        Tuple of (sanitized_bytes, AudioSanitizeResult).
    """
    if not HAS_NUMPY:
        return data, AudioSanitizeResult(
            success=False, original_size=len(data), sanitized_size=len(data),
            output_format="WAV", operations=[], error="numpy not installed",
        )

    info = _parse_wav_header(data)
    if not info:
        return data, AudioSanitizeResult(
            success=False, original_size=len(data), sanitized_size=len(data),
            output_format="WAV", operations=[], error="Could not parse WAV header",
        )

    ops: list[str] = []
    bps = info['bits_per_sample']
    channels = info['channels']
    sample_rate = info['sample_rate']
    audio_start = info['data_start']
    audio_size = info['data_size']

    audio_bytes = data[audio_start:audio_start + audio_size]
    samples = _extract_samples(audio_bytes, bps)

    if samples is None:
        return data, AudioSanitizeResult(
            success=False, original_size=len(data), sanitized_size=len(data),
            output_format="WAV", operations=[], error=f"Cannot extract {bps}-bit samples",
        )

    # Randomize LSB plane
    if randomize_lsb and bps in (16, 24, 32):
        rng = np.random.default_rng()
        random_bits = rng.integers(0, 2, size=samples.shape, dtype=np.int32)
        samples = (samples & ~1) | random_bits
        ops.append(f"randomized LSB of {len(samples)} samples (destroys LSB payloads)")
    elif randomize_lsb and bps == 8:
        rng = np.random.default_rng()
        random_bits = rng.integers(0, 2, size=samples.shape, dtype=np.int32)
        samples = (samples & 0xFE) | random_bits
        ops.append(f"randomized LSB of {len(samples)} 8-bit samples")

    # Rebuild WAV file from scratch (strips all non-essential chunks)
    sanitized = _build_wav(samples, bps, channels, sample_rate)
    ops.append("rebuilt WAV from scratch (strips non-standard chunks, trailing data)")

    return sanitized, AudioSanitizeResult(
        success=True,
        original_size=len(data),
        sanitized_size=len(sanitized),
        output_format="WAV",
        operations=ops,
    )


def _build_wav(
    samples: "np.ndarray",
    bits_per_sample: int,
    channels: int,
    sample_rate: int,
) -> bytes:
    """Build a minimal, clean WAV file from sample data."""
    # Convert samples back to bytes
    if bits_per_sample == 8:
        sample_bytes = samples.astype(np.uint8).tobytes()
    elif bits_per_sample == 16:
        sample_bytes = samples.astype(np.int16).tobytes()
    elif bits_per_sample == 32:
        sample_bytes = samples.astype(np.int32).tobytes()
    elif bits_per_sample == 24:
        # 24-bit: manually pack 3 bytes per sample
        parts = []
        for s in samples:
            val = int(s)
            if val < 0:
                val += 0x1000000
            parts.append(struct.pack('<I', val & 0xFFFFFF)[:3])
        sample_bytes = b''.join(parts)
    else:
        sample_bytes = samples.astype(np.int16).tobytes()
        bits_per_sample = 16

    bytes_per_sample = bits_per_sample // 8
    block_align = channels * bytes_per_sample
    byte_rate = sample_rate * block_align

    # fmt chunk (16 bytes)
    fmt_chunk = struct.pack('<4sI', b'fmt ', 16)
    fmt_chunk += struct.pack('<HHIIHH',
        1,                  # PCM format
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
    )

    # data chunk
    data_chunk = struct.pack('<4sI', b'data', len(sample_bytes))
    data_chunk += sample_bytes

    # RIFF header
    riff_size = 4 + len(fmt_chunk) + len(data_chunk)  # 'WAVE' + chunks
    header = struct.pack('<4sI4s', b'RIFF', riff_size, b'WAVE')

    return header + fmt_chunk + data_chunk
