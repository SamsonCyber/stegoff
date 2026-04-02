"""
Audio steganography detection.

Covers: WAV/PCM LSB analysis, spectral anomalies, trailing data,
metadata hiding, sample value distribution analysis.

Audio steg techniques hide data in:
  - LSBs of PCM samples (same principle as image LSB)
  - Phase coding (modifying phase of frequency components)
  - Spread spectrum (spreading data across frequency bands)
  - Echo hiding (adding micro-echoes with data-dependent delays)
  - Metadata fields (ID3 tags, RIFF chunks)
"""

from __future__ import annotations

import struct
from stegoff.report import Finding, Severity, StegMethod

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


# ─── WAV Structure Parsing ───────────────────────────────────────────────────

def _parse_wav_header(data: bytes) -> dict | None:
    """Parse WAV/RIFF header to extract format info."""
    if len(data) < 44:
        return None
    if data[:4] != b'RIFF' or data[8:12] != b'WAVE':
        return None

    try:
        riff_size = struct.unpack('<I', data[4:8])[0]

        # Find fmt chunk
        pos = 12
        fmt_info = None
        data_start = None
        data_size = None
        chunks = []

        while pos + 8 <= len(data):
            chunk_id = data[pos:pos+4]
            chunk_size = struct.unpack('<I', data[pos+4:pos+8])[0]
            chunks.append((chunk_id.decode('ascii', errors='replace'), chunk_size, pos))

            if chunk_id == b'fmt ':
                if pos + 8 + chunk_size <= len(data):
                    fmt_data = data[pos+8:pos+8+chunk_size]
                    if len(fmt_data) >= 16:
                        audio_fmt = struct.unpack('<H', fmt_data[0:2])[0]
                        channels = struct.unpack('<H', fmt_data[2:4])[0]
                        sample_rate = struct.unpack('<I', fmt_data[4:8])[0]
                        bits_per_sample = struct.unpack('<H', fmt_data[14:16])[0]
                        fmt_info = {
                            'audio_format': audio_fmt,
                            'channels': channels,
                            'sample_rate': sample_rate,
                            'bits_per_sample': bits_per_sample,
                        }

            elif chunk_id == b'data':
                data_start = pos + 8
                data_size = chunk_size

            pos += 8 + chunk_size
            # Align to word boundary
            if chunk_size % 2 == 1:
                pos += 1

        if fmt_info and data_start is not None:
            fmt_info['data_start'] = data_start
            fmt_info['data_size'] = data_size
            fmt_info['riff_size'] = riff_size
            fmt_info['file_size'] = len(data)
            fmt_info['chunks'] = chunks
            return fmt_info

    except (struct.error, IndexError):
        pass

    return None


# ─── AIFF Structure Parsing ─────────────────────────────────────────────────

def _parse_aiff_header(data: bytes) -> dict | None:
    """Parse AIFF/AIFF-C header to extract format info."""
    if len(data) < 12:
        return None
    if data[:4] != b'FORM' or data[8:12] not in (b'AIFF', b'AIFC'):
        return None

    try:
        pos = 12
        channels = None
        sample_rate = None
        bits_per_sample = None
        data_start = None
        data_size = None

        while pos + 8 <= len(data):
            chunk_id = data[pos:pos+4]
            chunk_size = struct.unpack('>I', data[pos+4:pos+8])[0]  # big-endian

            if chunk_id == b'COMM':
                if pos + 8 + chunk_size <= len(data):
                    comm = data[pos+8:pos+8+chunk_size]
                    if len(comm) >= 8:
                        channels = struct.unpack('>h', comm[0:2])[0]
                        bits_per_sample = struct.unpack('>h', comm[6:8])[0]
                        # Sample rate is 80-bit extended float, approximate it
                        sample_rate = 44100  # default fallback

            elif chunk_id == b'SSND':
                # SSND has 8 bytes offset+blockSize before audio data
                data_start = pos + 8 + 8
                data_size = chunk_size - 8

            pos += 8 + chunk_size
            if chunk_size % 2 == 1:
                pos += 1

        if channels and bits_per_sample and data_start:
            return {
                'audio_format': 1,  # PCM
                'channels': channels,
                'sample_rate': sample_rate or 44100,
                'bits_per_sample': bits_per_sample,
                'data_start': data_start,
                'data_size': data_size or 0,
                'file_size': len(data),
                'format_name': 'AIFF',
                'endian': 'big',
            }
    except (struct.error, IndexError):
        pass
    return None


# ─── AU Structure Parsing ───────────────────────────────────────────────────

def _parse_au_header(data: bytes) -> dict | None:
    """Parse Sun/NeXT AU audio header."""
    if len(data) < 24:
        return None
    if data[:4] != b'.snd':
        return None

    try:
        data_offset = struct.unpack('>I', data[4:8])[0]
        data_size = struct.unpack('>I', data[8:12])[0]
        encoding = struct.unpack('>I', data[12:16])[0]
        sample_rate = struct.unpack('>I', data[16:20])[0]
        channels = struct.unpack('>I', data[20:24])[0]

        # AU encoding: 2=8-bit linear, 3=16-bit linear, 4=24-bit, 5=32-bit
        bps_map = {2: 8, 3: 16, 4: 24, 5: 32}
        bits_per_sample = bps_map.get(encoding)
        if not bits_per_sample:
            return None

        if data_size == 0xFFFFFFFF:
            data_size = len(data) - data_offset

        return {
            'audio_format': 1,  # PCM
            'channels': channels,
            'sample_rate': sample_rate,
            'bits_per_sample': bits_per_sample,
            'data_start': data_offset,
            'data_size': data_size,
            'file_size': len(data),
            'format_name': 'AU',
            'endian': 'big',
        }
    except (struct.error, IndexError):
        pass
    return None


# ─── LSB Analysis for Audio ─────────────────────────────────────────────────

def detect_audio_lsb(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect LSB steganography in WAV, AIFF, and AU audio files.

    Audio LSB steg replaces the least-significant bit of each PCM sample
    with payload data. Detection: natural audio has correlated LSBs
    (quiet passages → LSBs track the signal). Embedded data makes the
    LSB plane random.
    """
    if not HAS_NUMPY:
        return []

    info = _parse_wav_header(data) or _parse_aiff_header(data) or _parse_au_header(data)
    if not info:
        return []

    # Only analyze uncompressed PCM (format 1)
    if info['audio_format'] != 1:
        return []

    bps = info['bits_per_sample']
    if bps not in (8, 16, 24, 32):
        return []

    # Extract samples
    audio_data = data[info['data_start']:info['data_start'] + info['data_size']]
    endian = info.get('endian', 'little')
    samples = _extract_samples(audio_data, bps, endian)

    if samples is None or len(samples) < 1000:
        return []

    findings = []

    # Test 1: LSB correlation analysis
    lsb_plane = samples & 1

    # Autocorrelation of LSB plane (lag-1)
    # Natural audio: adjacent samples are correlated → LSBs correlate
    # Steg audio: LSBs are random → correlation drops to ~0.50
    if len(lsb_plane) > 1:
        correlation = np.mean(lsb_plane[:-1] == lsb_plane[1:])

        if correlation < 0.505:
            # Very close to random (0.500)
            severity = Severity.CRITICAL
            confidence = 0.90
        elif correlation < 0.52:
            severity = Severity.HIGH
            confidence = 0.75
        elif correlation < 0.54:
            severity = Severity.MEDIUM
            confidence = 0.55
        else:
            severity = None

        if severity:
            findings.append(Finding(
                method=StegMethod.LSB,
                severity=severity,
                confidence=confidence,
                description=f"Audio LSB plane shows noise-like pattern (correlation={correlation:.4f})",
                evidence=(
                    f"LSB autocorrelation={correlation:.4f} (random=0.500, natural>0.55), "
                    f"samples={len(samples)}, bits_per_sample={bps}"
                ),
                location="audio PCM data",
                metadata={
                    "lsb_correlation": round(correlation, 4),
                    "sample_count": len(samples),
                    "bits_per_sample": bps,
                    "channels": info['channels'],
                    "sample_rate": info['sample_rate'],
                },
            ))

    # Test 2: Chi-square on LSB pairs (same as image chi-square)
    chi_sq_result = _audio_chi_square(samples)
    if chi_sq_result:
        chi_sq, p_value = chi_sq_result
        if p_value < 0.05:
            embedding_rate = max(0.0, min(1.0, 1.0 - (p_value * 2)))
            severity = Severity.CRITICAL if embedding_rate > 0.3 else Severity.HIGH
            confidence = min(0.90, 1.0 - p_value)

            findings.append(Finding(
                method=StegMethod.LSB,
                severity=severity,
                confidence=confidence,
                description="Audio sample pairs show chi-square anomaly (LSB embedding)",
                evidence=f"chi2={chi_sq:.2f}, p={p_value:.6f}, rate≈{embedding_rate:.1%}",
                location="audio PCM data",
                metadata={
                    "chi_square": round(chi_sq, 4),
                    "p_value": round(p_value, 8),
                    "embedding_rate": round(embedding_rate, 4),
                },
            ))

    # Test 3: Entropy of LSB plane segments
    # Divide LSB plane into blocks, measure entropy of each
    block_size = min(4096, len(lsb_plane) // 10)
    if block_size >= 256:
        entropies = []
        for i in range(0, len(lsb_plane) - block_size, block_size):
            block = lsb_plane[i:i+block_size]
            ones_ratio = np.mean(block)
            # Shannon entropy for binary
            if 0 < ones_ratio < 1:
                h = -ones_ratio * np.log2(ones_ratio) - (1-ones_ratio) * np.log2(1-ones_ratio)
            else:
                h = 0.0
            entropies.append(h)

        avg_entropy = np.mean(entropies)
        min_entropy = np.min(entropies)

        # Perfect random = entropy of 1.0. Natural audio < 0.95 on average.
        # Fully embedded steg → all blocks near 1.0 (uniform randomness).
        if avg_entropy > 0.995 and min_entropy > 0.98:
            findings.append(Finding(
                method=StegMethod.LSB,
                severity=Severity.HIGH,
                confidence=0.80,
                description="Audio LSB entropy uniformly maximal across all segments",
                evidence=(
                    f"avg_entropy={avg_entropy:.4f}, min_entropy={min_entropy:.4f} "
                    f"({len(entropies)} blocks of {block_size} samples)"
                ),
                location="audio PCM data",
                metadata={
                    "avg_entropy": round(avg_entropy, 4),
                    "min_entropy": round(min_entropy, 4),
                    "block_count": len(entropies),
                },
            ))

    return findings


def _extract_samples(audio_data: bytes, bits_per_sample: int, endian: str = "little") -> "np.ndarray | None":
    """Extract PCM samples from raw audio data as integer array."""
    try:
        if bits_per_sample == 8:
            return np.frombuffer(audio_data, dtype=np.uint8).astype(np.int32)
        elif bits_per_sample == 16:
            dtype = np.dtype('>i2') if endian == 'big' else np.dtype('<i2')
            return np.frombuffer(audio_data, dtype=dtype).astype(np.int32)
        elif bits_per_sample == 24:
            n = len(audio_data) // 3
            samples = np.zeros(n, dtype=np.int32)
            for i in range(n):
                b = audio_data[i*3:(i+1)*3]
                if endian == 'big':
                    val = (b[0] << 16) | (b[1] << 8) | b[2]
                else:
                    val = b[0] | (b[1] << 8) | (b[2] << 16)
                if val & 0x800000:
                    val -= 0x1000000
                samples[i] = val
            return samples
        elif bits_per_sample == 32:
            dtype = np.dtype('>i4') if endian == 'big' else np.dtype('<i4')
            return np.frombuffer(audio_data, dtype=dtype).astype(np.int32)
    except (ValueError, IndexError):
        pass
    return None


def _audio_chi_square(samples: "np.ndarray") -> tuple[float, float] | None:
    """Chi-square test on audio sample value pairs."""
    # Use only low 8 bits to keep histogram manageable
    low_bits = np.abs(samples) & 0xFF

    hist = np.bincount(low_bits.astype(np.int32), minlength=256)

    chi_sq = 0.0
    pairs = 0
    for k in range(128):
        obs_even = float(hist[2 * k])
        obs_odd = float(hist[2 * k + 1])
        expected = (obs_even + obs_odd) / 2.0
        if expected > 5:
            chi_sq += ((obs_even - expected) ** 2) / expected
            chi_sq += ((obs_odd - expected) ** 2) / expected
            pairs += 1

    if pairs == 0:
        return None

    try:
        from scipy.stats import chi2
        p_value = 1.0 - chi2.cdf(chi_sq, pairs)
    except ImportError:
        if chi_sq > pairs * 3:
            p_value = 0.001
        elif chi_sq > pairs * 2:
            p_value = 0.01
        elif chi_sq > pairs * 1.5:
            p_value = 0.05
        else:
            p_value = 0.5

    return chi_sq, p_value


# ─── Structural Analysis ────────────────────────────────────────────────────

def detect_audio_structural(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect structural anomalies in audio files.

    Checks: trailing data after RIFF, non-standard chunks,
    metadata size anomalies, file size vs declared size mismatch.
    """
    findings = []

    # WAV trailing data
    if data[:4] == b'RIFF' and len(data) >= 8:
        riff_size = struct.unpack('<I', data[4:8])[0]
        declared_total = riff_size + 8  # RIFF header is 8 bytes
        actual = len(data)

        if actual > declared_total + 10:
            trailing = actual - declared_total
            findings.append(Finding(
                method=StegMethod.TRAILING_DATA,
                severity=Severity.CRITICAL,
                confidence=0.92,
                description=f"{trailing} bytes after declared RIFF end in WAV file",
                evidence=f"declared={declared_total}, actual={actual}, trailing preview: {data[declared_total:declared_total+40].hex()}",
                location="after RIFF boundary",
                metadata={"trailing_bytes": trailing, "format": "WAV"},
            ))

    # Check for non-standard RIFF chunks (data can be hidden in custom chunks)
    info = _parse_wav_header(data)
    if info and 'chunks' in info:
        standard_chunks = {b'RIFF', b'WAVE', b'fmt ', b'data', b'LIST', b'fact',
                          b'cue ', b'plst', b'list', b'labl', b'note', b'ltxt',
                          b'smpl', b'inst', b'DISP', b'JUNK', b'PAD ', b'bext',
                          b'iXML', b'PEAK', b'afsp', b'cart'}

        for chunk_id, chunk_size, chunk_pos in info['chunks']:
            chunk_bytes = chunk_id.encode('ascii', errors='replace')
            if chunk_bytes not in standard_chunks and chunk_size > 100:
                findings.append(Finding(
                    method=StegMethod.EMBEDDED_FILE,
                    severity=Severity.HIGH,
                    confidence=0.70,
                    description=f"Non-standard RIFF chunk '{chunk_id}' ({chunk_size} bytes)",
                    evidence=f"chunk at offset {chunk_pos}",
                    location=f"RIFF chunk '{chunk_id}'",
                    metadata={"chunk_id": chunk_id, "chunk_size": chunk_size},
                ))

    # MP3: check for oversized ID3 tags
    if data[:3] == b'ID3' and len(data) >= 10:
        # ID3v2 size is syncsafe integer in bytes 6-9
        size_bytes = data[6:10]
        tag_size = (
            (size_bytes[0] & 0x7F) << 21 |
            (size_bytes[1] & 0x7F) << 14 |
            (size_bytes[2] & 0x7F) << 7 |
            (size_bytes[3] & 0x7F)
        )
        if tag_size > 100_000:  # 100KB+ ID3 tag is suspicious
            findings.append(Finding(
                method=StegMethod.METADATA_EXIF,
                severity=Severity.MEDIUM,
                confidence=0.55,
                description=f"Unusually large ID3 tag ({tag_size} bytes) in MP3",
                evidence=f"ID3v2 tag size: {tag_size} bytes",
                metadata={"id3_size": tag_size},
            ))

    return findings


# ─── Master audio scanner ────────────────────────────────────────────────────

def scan_audio(data: bytes, filepath: str = "") -> list[Finding]:
    """Run all audio steganography detectors."""
    findings: list[Finding] = []
    findings.extend(detect_audio_lsb(data, filepath))
    findings.extend(detect_audio_structural(data, filepath))
    return findings
