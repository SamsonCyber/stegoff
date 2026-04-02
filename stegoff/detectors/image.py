"""
Image steganography detection — statistical and structural analysis.

Covers: LSB, F5/DCT, PVD, palette manipulation, PNG chunks,
trailing data, EXIF metadata, bit-plane anomalies.
"""

from __future__ import annotations
import io
import re
import struct
import zlib

from stegoff.report import Finding, Severity, StegMethod

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from PIL import Image as PILImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ─── LSB Detection ──────────────────────────────────────────────────────────

def detect_lsb_chi_square(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Chi-square analysis for LSB steganography.

    Compares observed LSB distribution against expected uniform distribution.
    Sequential LSB embedding creates detectable statistical anomalies in
    pairs of values (2k, 2k+1) — their frequencies should be roughly equal
    in cover images but diverge predictably when data is embedded.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
        if img.mode not in ('RGB', 'RGBA', 'L'):
            img = img.convert('RGB')
        pixels = np.array(img)
    except Exception:
        return []

    findings = []

    # Flatten to channel arrays
    if len(pixels.shape) == 3:
        channels = {'R': pixels[:, :, 0], 'G': pixels[:, :, 1], 'B': pixels[:, :, 2]}
    else:
        channels = {'Gray': pixels}

    for ch_name, ch_data in channels.items():
        flat = ch_data.flatten()
        chi_sq, p_value, embedding_rate = _chi_square_test(flat)

        if p_value < 0.05:  # Statistically significant
            if embedding_rate > 0.3:
                severity = Severity.CRITICAL
                confidence = min(0.95, 1.0 - p_value)
            elif embedding_rate > 0.1:
                severity = Severity.HIGH
                confidence = min(0.85, 1.0 - p_value)
            else:
                severity = Severity.MEDIUM
                confidence = 0.70

            findings.append(Finding(
                method=StegMethod.LSB,
                severity=severity,
                confidence=confidence,
                description=f"LSB embedding detected in {ch_name} channel (chi-square test)",
                evidence=(
                    f"chi2={chi_sq:.2f}, p={p_value:.6f}, "
                    f"estimated embedding rate={embedding_rate:.1%}"
                ),
                location=f"channel: {ch_name}",
                metadata={
                    "channel": ch_name,
                    "chi_square": round(chi_sq, 4),
                    "p_value": round(p_value, 8),
                    "embedding_rate": round(embedding_rate, 4),
                },
            ))

    return findings


def _chi_square_test(values: "np.ndarray") -> tuple[float, float, float]:
    """Perform chi-square test on pixel value pairs."""
    import numpy as np

    # Count occurrences of each value 0-255
    hist = np.bincount(values.astype(np.int32), minlength=256)

    # Pair analysis: (2k) and (2k+1) should have equal frequency in steg-free images
    chi_sq = 0.0
    pairs = 0
    for k in range(128):
        observed_even = hist[2 * k]
        observed_odd = hist[2 * k + 1]
        expected = (observed_even + observed_odd) / 2.0
        if expected > 5:  # Standard chi-square requirement
            chi_sq += ((observed_even - expected) ** 2) / expected
            chi_sq += ((observed_odd - expected) ** 2) / expected
            pairs += 1

    if pairs == 0:
        return 0.0, 1.0, 0.0

    # Degrees of freedom = number of pairs
    # Approximate p-value using scipy if available, otherwise estimate
    try:
        from scipy.stats import chi2
        p_value = 1.0 - chi2.cdf(chi_sq, pairs)
    except ImportError:
        # Rough approximation: very high chi-sq = very low p-value
        if chi_sq > pairs * 3:
            p_value = 0.001
        elif chi_sq > pairs * 2:
            p_value = 0.01
        elif chi_sq > pairs * 1.5:
            p_value = 0.05
        else:
            p_value = 0.5

    # Estimate embedding rate from chi-square deviation
    embedding_rate = max(0.0, min(1.0, 1.0 - (p_value * 2)))

    return chi_sq, p_value, embedding_rate


def detect_lsb_rs_analysis(data: bytes, filepath: str = "") -> list[Finding]:
    """
    RS (Regular-Singular) analysis — academic gold standard for LSB detection.

    Divides image into groups, applies flipping functions, and compares
    regular/singular group ratios. Embedding distorts the R/S relationship.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
        if img.mode not in ('RGB', 'RGBA', 'L'):
            img = img.convert('RGB')
        pixels = np.array(img, dtype=np.float64)
    except Exception:
        return []

    findings = []

    if len(pixels.shape) == 3:
        channels = {'R': pixels[:, :, 0], 'G': pixels[:, :, 1], 'B': pixels[:, :, 2]}
    else:
        channels = {'Gray': pixels}

    for ch_name, ch_data in channels.items():
        estimated_length = _rs_analysis(ch_data)

        if estimated_length > 0.05:  # More than 5% of capacity used
            if estimated_length > 0.3:
                severity = Severity.CRITICAL
                confidence = 0.92
            elif estimated_length > 0.15:
                severity = Severity.HIGH
                confidence = 0.80
            else:
                severity = Severity.MEDIUM
                confidence = 0.65

            findings.append(Finding(
                method=StegMethod.LSB,
                severity=severity,
                confidence=confidence,
                description=f"RS analysis detects LSB embedding in {ch_name} channel",
                evidence=f"estimated message length: {estimated_length:.1%} of capacity",
                location=f"channel: {ch_name}",
                metadata={
                    "channel": ch_name,
                    "estimated_length_ratio": round(estimated_length, 4),
                    "analysis_method": "RS",
                },
            ))

    return findings


def _rs_analysis(channel: "np.ndarray", group_size: int = 4) -> float:
    """
    Perform RS analysis on a single channel.
    Returns estimated embedding rate (0.0 = clean, 1.0 = fully embedded).
    """
    import numpy as np

    h, w = channel.shape
    # Trim to fit group_size
    h = h - (h % group_size)
    w = w - (w % group_size)
    channel = channel[:h, :w]

    flat = channel.flatten()
    n_groups = len(flat) // group_size

    if n_groups < 100:
        return 0.0

    groups = flat[:n_groups * group_size].reshape(n_groups, group_size)

    def discrimination(group):
        """Smoothness measure: sum of absolute differences."""
        return np.sum(np.abs(np.diff(group)))

    def flip_positive(group):
        """F1 flipping: 0<->1, 2<->3, etc."""
        g = group.copy()
        g = np.where(g % 2 == 0, g + 1, g - 1)
        return g

    def flip_negative(group):
        """F-1 flipping: -1<->0, 1<->2, etc."""
        g = group.copy()
        mask = g % 2 == 0
        g[mask] -= 1
        g[~mask] += 1
        return np.clip(g, 0, 255)

    # Count Regular, Singular groups for F1 and F-1
    rm, sm, r_m, s_m = 0, 0, 0, 0

    for group in groups:
        d_orig = discrimination(group)

        d_f1 = discrimination(flip_positive(group))
        if d_f1 > d_orig:
            rm += 1
        elif d_f1 < d_orig:
            sm += 1

        d_fn1 = discrimination(flip_negative(group))
        if d_fn1 > d_orig:
            r_m += 1
        elif d_fn1 < d_orig:
            s_m += 1

    total = n_groups
    if total == 0:
        return 0.0

    rm_r = rm / total
    sm_r = sm / total
    r_m_r = r_m / total
    s_m_r = s_m / total

    # In clean images: Rm ≈ R-m and Sm ≈ S-m
    # In steg images: Rm > R-m or Sm < S-m
    # Estimate embedding rate from the deviation
    d1 = abs(rm_r - r_m_r)
    d2 = abs(sm_r - s_m_r)

    # Simplified estimation (full quadratic solver omitted for clarity)
    estimated_rate = (d1 + d2) / 2.0
    return min(estimated_rate * 2, 1.0)  # Scale up, cap at 1.0


def detect_lsb_sample_pairs(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Sample Pairs analysis for LSB detection.

    Examines adjacent pixel pairs and their trace statistics.
    More accurate than chi-square for small payloads.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
        if img.mode not in ('RGB', 'RGBA', 'L'):
            img = img.convert('RGB')
        pixels = np.array(img)
    except Exception:
        return []

    findings = []

    if len(pixels.shape) == 3:
        channels = {'R': pixels[:, :, 0], 'G': pixels[:, :, 1], 'B': pixels[:, :, 2]}
    else:
        channels = {'Gray': pixels}

    for ch_name, ch_data in channels.items():
        flat = ch_data.flatten().astype(np.int32)
        if len(flat) < 200:
            continue

        # Count trace subsets
        # Pairs (u, v) where u = flat[2i], v = flat[2i+1]
        n = len(flat) // 2
        u = flat[:2*n:2]
        v = flat[1:2*n:2]

        # Closed-form sample pairs estimator
        # Count pairs in different categories
        Cm = np.sum((u // 2) == (v // 2))          # same pair
        Dm = np.sum(np.abs(u // 2 - v // 2) == 1)  # adjacent pairs

        if Cm + Dm == 0:
            continue

        # Ratio-based estimate
        beta = Cm / (Cm + Dm) if (Cm + Dm) > 0 else 0.5
        # In clean images, beta ≈ specific value. Deviation = embedding.
        # This is a simplified version of the full SP estimator.
        embedding_estimate = max(0.0, 2 * abs(beta - 0.5))

        if embedding_estimate > 0.1:
            severity = Severity.HIGH if embedding_estimate > 0.25 else Severity.MEDIUM
            confidence = min(0.85, 0.5 + embedding_estimate)

            findings.append(Finding(
                method=StegMethod.LSB,
                severity=severity,
                confidence=confidence,
                description=f"Sample Pairs analysis detects LSB anomaly in {ch_name}",
                evidence=f"beta={beta:.4f}, estimated embedding={embedding_estimate:.1%}",
                location=f"channel: {ch_name}",
                metadata={
                    "channel": ch_name,
                    "beta": round(beta, 4),
                    "estimated_embedding": round(embedding_estimate, 4),
                    "analysis_method": "SamplePairs",
                },
            ))

    return findings


# ─── DCT / F5 Detection ─────────────────────────────────────────────────────

def detect_dct_anomaly(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect F5/DCT-based steganography in JPEG images.

    F5 embeds data in DCT coefficients. This causes a characteristic
    "histogram hole" at zero and asymmetry in coefficient distribution.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return []

    # Quick check: is this a JPEG?
    if data[:2] != b'\xff\xd8':
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
        if img.format != 'JPEG':
            return []

        # We need to analyze DCT coefficients
        # PIL doesn't expose raw DCT, but we can check quantization tables
        # and do statistical analysis on the decompressed pixel data
        pixels = np.array(img.convert('L'), dtype=np.float64)
    except Exception:
        return []

    # Blockiness analysis: JPEG compression creates 8x8 block artifacts
    # F5 embedding changes the blockiness pattern
    h, w = pixels.shape
    h8, w8 = h - (h % 8), w - (w % 8)
    if h8 < 16 or w8 < 16:
        return []

    pixels = pixels[:h8, :w8]

    # Measure blockiness: compare variance at block boundaries vs interior
    boundary_diffs = []
    interior_diffs = []

    for y in range(0, h8 - 1):
        for x in range(0, w8 - 1):
            diff = abs(float(pixels[y, x]) - float(pixels[y, x + 1]))
            if (x + 1) % 8 == 0:
                boundary_diffs.append(diff)
            else:
                interior_diffs.append(diff)

    if not boundary_diffs or not interior_diffs:
        return []

    avg_boundary = np.mean(boundary_diffs)
    avg_interior = np.mean(interior_diffs)

    # Blockiness ratio: higher = more block artifacts = normal JPEG
    # F5 can reduce blockiness slightly compared to the same quality level
    blockiness = avg_boundary / max(avg_interior, 0.001)

    # Also check for coefficient histogram anomalies via pixel-domain proxy
    # The "calibration" technique: crop image by 4 pixels, re-analyze
    if h8 > 16 and w8 > 16:
        cropped = pixels[4:h8-4, 4:w8-4]
        ch, cw = cropped.shape
        ch8, cw8 = ch - (ch % 8), cw - (cw % 8)
        cropped = cropped[:ch8, :cw8]

        crop_boundary = []
        crop_interior = []
        for y in range(0, ch8 - 1):
            for x in range(0, cw8 - 1):
                diff = abs(float(cropped[y, x]) - float(cropped[y, x + 1]))
                if (x + 1) % 8 == 0:
                    crop_boundary.append(diff)
                else:
                    crop_interior.append(diff)

        if crop_boundary and crop_interior:
            crop_blockiness = np.mean(crop_boundary) / max(np.mean(crop_interior), 0.001)

            # Calibration difference: significant change suggests DCT manipulation
            calibration_diff = abs(blockiness - crop_blockiness) / max(blockiness, 0.001)

            if calibration_diff > 0.15:
                severity = Severity.HIGH if calibration_diff > 0.3 else Severity.MEDIUM
                confidence = min(0.80, 0.5 + calibration_diff)

                return [Finding(
                    method=StegMethod.DCT_F5,
                    severity=severity,
                    confidence=confidence,
                    description="DCT coefficient anomaly detected (possible F5 embedding)",
                    evidence=(
                        f"blockiness={blockiness:.4f}, "
                        f"calibrated={crop_blockiness:.4f}, "
                        f"deviation={calibration_diff:.1%}"
                    ),
                    metadata={
                        "blockiness": round(blockiness, 4),
                        "calibrated_blockiness": round(crop_blockiness, 4),
                        "calibration_diff": round(calibration_diff, 4),
                    },
                )]

    return []


# ─── Bit Plane Analysis ─────────────────────────────────────────────────────

def detect_bit_plane_anomaly(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Analyze bit planes for embedding artifacts.

    LSB embedding makes the least-significant bit plane look random.
    Natural images have structured LSB planes with spatial correlation.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
        if img.mode not in ('RGB', 'RGBA', 'L'):
            img = img.convert('RGB')
        pixels = np.array(img)
    except Exception:
        return []

    findings = []

    if len(pixels.shape) == 3:
        channels = {'R': pixels[:, :, 0], 'G': pixels[:, :, 1], 'B': pixels[:, :, 2]}
    else:
        channels = {'Gray': pixels}

    for ch_name, ch_data in channels.items():
        # Extract LSB plane
        lsb_plane = ch_data & 1

        # Measure spatial correlation in LSB plane
        # Natural images: LSB plane has spatial structure
        # Steg images: LSB plane approaches random noise
        h, w = lsb_plane.shape
        if h < 10 or w < 10:
            continue

        # Horizontal correlation
        h_corr = np.mean(lsb_plane[:, :-1] == lsb_plane[:, 1:])
        # Vertical correlation
        v_corr = np.mean(lsb_plane[:-1, :] == lsb_plane[1:, :])

        avg_corr = (h_corr + v_corr) / 2.0

        # Random noise: correlation ≈ 0.5. Natural image LSB: correlation > 0.55
        if avg_corr < 0.52:
            severity = Severity.HIGH
            confidence = 0.80
        elif avg_corr < 0.54:
            severity = Severity.MEDIUM
            confidence = 0.60
        else:
            continue

        # Also check entropy of LSB plane
        ones_ratio = np.mean(lsb_plane)
        entropy_deviation = abs(ones_ratio - 0.5)

        findings.append(Finding(
            method=StegMethod.BIT_PLANE_ANOMALY,
            severity=severity,
            confidence=confidence,
            description=f"LSB plane in {ch_name} shows noise-like pattern (low spatial correlation)",
            evidence=(
                f"spatial_correlation={avg_corr:.4f} (random=0.50, natural>0.55), "
                f"ones_ratio={ones_ratio:.4f}"
            ),
            location=f"channel: {ch_name}, bit plane: 0",
            metadata={
                "channel": ch_name,
                "h_correlation": round(h_corr, 4),
                "v_correlation": round(v_corr, 4),
                "ones_ratio": round(ones_ratio, 4),
                "entropy_deviation": round(entropy_deviation, 4),
            },
        ))

    return findings


# ─── PVD Detection ───────────────────────────────────────────────────────────

def detect_pvd(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect Pixel Value Differencing steganography.

    PVD embeds data in the differences between adjacent pixel pairs.
    Detection: the difference histogram of steg images shows step artifacts
    at range boundaries.
    """
    if not HAS_PIL or not HAS_NUMPY:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
        pixels = np.array(img.convert('L'), dtype=np.int32)
    except Exception:
        return []

    h, w = pixels.shape
    if h < 10 or w < 10:
        return []

    # Compute horizontal pixel differences
    diffs = np.abs(pixels[:, :-1] - pixels[:, 1:]).flatten()

    # PVD range boundaries (Wu-Tsai scheme): 0-7, 8-15, 16-31, 32-63, 64-127, 128-255
    boundaries = [8, 16, 32, 64, 128]

    # Check for step artifacts at boundaries
    hist = np.bincount(np.clip(diffs, 0, 255), minlength=256)

    anomaly_score = 0.0
    for b in boundaries:
        if b < 255:
            # Sharp drop or rise at boundary = PVD artifact
            left = float(hist[b - 1]) if b > 0 else 0
            right = float(hist[b])
            if left + right > 0:
                ratio = abs(left - right) / max(left, right, 1)
                if ratio > 0.5:
                    anomaly_score += ratio

    anomaly_score /= len(boundaries)

    if anomaly_score > 0.2:
        severity = Severity.HIGH if anomaly_score > 0.4 else Severity.MEDIUM
        confidence = min(0.75, 0.4 + anomaly_score)

        return [Finding(
            method=StegMethod.PVD,
            severity=severity,
            confidence=confidence,
            description="Pixel Value Differencing anomaly in difference histogram",
            evidence=f"boundary anomaly score={anomaly_score:.4f}",
            metadata={"anomaly_score": round(anomaly_score, 4)},
        )]

    return []


# ─── PNG Chunk Analysis ──────────────────────────────────────────────────────

def detect_png_chunks(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect suspicious ancillary chunks in PNG files.

    PNG allows arbitrary named chunks. Steganography tools hide data
    in custom/non-standard chunks or inflate standard ancillary chunks.
    """
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return []

    findings = []
    STANDARD_CHUNKS = {
        b'IHDR', b'PLTE', b'IDAT', b'IEND',  # Critical
        b'cHRM', b'gAMA', b'iCCP', b'sBIT', b'sRGB',  # Color
        b'bKGD', b'hIST', b'tRNS',  # Transparency
        b'pHYs', b'sPLT',  # Pixel dimensions
        b'tIME', b'tEXt', b'zTXt', b'iTXt',  # Text
        b'eXIf',  # EXIF
    }

    pos = 8  # After PNG signature
    suspicious_chunks = []
    text_chunks = []

    while pos + 8 <= len(data):
        if pos + 4 > len(data):
            break
        length = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        chunk_data = data[pos+8:pos+8+length] if pos + 8 + length <= len(data) else b''
        pos += 12 + length  # 4 length + 4 type + data + 4 CRC

        if chunk_type == b'IEND':
            # Check for data after IEND
            remaining = len(data) - pos
            if remaining > 0:
                findings.append(Finding(
                    method=StegMethod.TRAILING_DATA,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    description=f"{remaining} bytes after PNG IEND chunk",
                    evidence=f"trailing data starts with: {data[pos:pos+50].hex()}",
                    metadata={"trailing_bytes": remaining},
                ))
            break

        if chunk_type not in STANDARD_CHUNKS:
            suspicious_chunks.append((chunk_type.decode('ascii', errors='replace'), length))

        # Check text chunks for hidden data
        if chunk_type in (b'tEXt', b'zTXt', b'iTXt'):
            try:
                if chunk_type == b'tEXt':
                    text_content = chunk_data.decode('latin-1', errors='replace')
                elif chunk_type == b'zTXt':
                    null_pos = chunk_data.find(b'\x00')
                    if null_pos >= 0 and null_pos + 2 < len(chunk_data):
                        text_content = zlib.decompress(chunk_data[null_pos+2:]).decode('latin-1', errors='replace')
                    else:
                        text_content = ""
                else:
                    text_content = chunk_data.decode('utf-8', errors='replace')

                if len(text_content) > 500:
                    text_chunks.append((chunk_type.decode(), len(text_content)))

                # Flag text chunks with suspicious content regardless of size
                _tc_lower = text_content.lower()
                if any(pat in _tc_lower for pat in (
                    'secret', 'hidden', 'payload', 'inject', 'ignore',
                    'decode', 'steg', 'encoded', 'base64',
                )):
                    findings.append(Finding(
                        method=StegMethod.PNG_CHUNKS,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        description="PNG text chunk contains suspicious keywords",
                        evidence=f"chunk {chunk_type.decode()}: {text_content[:200]}",
                        metadata={"chunk_type": chunk_type.decode(), "size": len(text_content)},
                    ))
                # Multiple text chunks beyond standard keys is suspicious
                _standard_keys = {'Title', 'Author', 'Description', 'Copyright',
                                  'Creation Time', 'Software', 'Disclaimer',
                                  'Warning', 'Source', 'Comment'}
                null_pos = text_content.find('\x00')
                key = text_content[:null_pos] if null_pos >= 0 else text_content[:40]
                if key and key not in _standard_keys and len(text_content) > 20:
                    text_chunks.append((chunk_type.decode(), len(text_content)))
            except Exception:
                pass

    if suspicious_chunks:
        findings.append(Finding(
            method=StegMethod.PNG_CHUNKS,
            severity=Severity.HIGH,
            confidence=0.80,
            description=f"{len(suspicious_chunks)} non-standard PNG chunk(s) detected",
            evidence="; ".join(f"'{name}' ({size} bytes)" for name, size in suspicious_chunks),
            metadata={"chunks": suspicious_chunks},
        ))

    if text_chunks:
        for chunk_name, size in text_chunks:
            if size > 1000:
                findings.append(Finding(
                    method=StegMethod.PNG_CHUNKS,
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    description=f"Unusually large text chunk '{chunk_name}' ({size} bytes)",
                    evidence=f"chunk type: {chunk_name}, size: {size}",
                    metadata={"chunk_type": chunk_name, "size": size},
                ))

    return findings


# ─── Trailing Data Detection ────────────────────────────────────────────────

def detect_trailing_data(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect data appended after the file format's end-of-file marker.

    Works for: JPEG (FFD9), PNG (IEND already handled), GIF (3B),
    ZIP (end of central directory).
    """
    findings = []

    # JPEG: ends with FF D9
    if data[:2] == b'\xff\xd8':
        eof_pos = data.rfind(b'\xff\xd9')
        if eof_pos >= 0:
            trailing = len(data) - eof_pos - 2
            if trailing > 0:
                findings.append(Finding(
                    method=StegMethod.TRAILING_DATA,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    description=f"{trailing} bytes after JPEG EOF marker",
                    evidence=f"data after FFD9: {data[eof_pos+2:eof_pos+52].hex()}",
                    metadata={"trailing_bytes": trailing, "format": "JPEG"},
                ))

    # GIF: ends with 0x3B
    if data[:3] in (b'GIF87a', b'GIF89a')[:1]:  # Check first 3 bytes
        if data[:6] in (b'GIF87a', b'GIF89a'):
            eof_pos = data.rfind(b'\x3b')
            if eof_pos >= 0:
                trailing = len(data) - eof_pos - 1
                if trailing > 10:  # Small tolerance for padding
                    findings.append(Finding(
                        method=StegMethod.TRAILING_DATA,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        description=f"{trailing} bytes after GIF EOF marker",
                        evidence=f"data after 3B: {data[eof_pos+1:eof_pos+51].hex()}",
                        metadata={"trailing_bytes": trailing, "format": "GIF"},
                    ))

    return findings


# ─── EXIF / Metadata Analysis ───────────────────────────────────────────────

def detect_metadata_hiding(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect suspicious EXIF/metadata content that may contain hidden data."""
    if not HAS_PIL:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
    except Exception:
        return []

    findings = []

    # Check for EXIF data
    exif_data = None
    try:
        exif_data = img.getexif()
    except Exception:
        pass

    if exif_data:
        # Look for unusually large or suspicious EXIF tags
        for tag_id, value in exif_data.items():
            if isinstance(value, (bytes, str)):
                size = len(value) if isinstance(value, bytes) else len(value.encode())
                if size > 1000:
                    findings.append(Finding(
                        method=StegMethod.METADATA_EXIF,
                        severity=Severity.MEDIUM,
                        confidence=0.60,
                        description=f"Unusually large EXIF tag {tag_id} ({size} bytes)",
                        evidence=f"tag {tag_id}: {str(value)[:100]}",
                        metadata={"tag_id": tag_id, "size": size},
                    ))

    # Check for IPTC, XMP, ICC with payloads or encoded content
    info = img.info if hasattr(img, 'info') else {}
    for key, value in info.items():
        if isinstance(value, (bytes, str)):
            val_str = value if isinstance(value, str) else value.decode('latin-1', errors='replace')
            # For binary fields (like icc_profile), check for embedded readable text
            if isinstance(value, bytes) and len(value) > 20:
                try:
                    # Scan for ASCII substrings within binary data
                    ascii_runs = []
                    current_run = []
                    for b in value:
                        if 32 <= b <= 126:
                            current_run.append(chr(b))
                        else:
                            if len(current_run) >= 10:
                                ascii_runs.append(''.join(current_run))
                            current_run = []
                    if len(current_run) >= 10:
                        ascii_runs.append(''.join(current_run))
                    if ascii_runs:
                        longest = max(ascii_runs, key=len)
                        if len(longest) >= 15:
                            findings.append(Finding(
                                method=StegMethod.METADATA_EXIF,
                                severity=Severity.HIGH,
                                confidence=0.80,
                                description=f"Readable text embedded in binary metadata field '{key}'",
                                evidence=f"Found: {longest[:150]}",
                                decoded_payload=longest[:500],
                                metadata={"field": key, "text_length": len(longest)},
                            ))
                except Exception:
                    pass
            size = len(val_str)
            if size > 2000 and key not in ('gamma', 'dpi', 'aspect'):
                findings.append(Finding(
                    method=StegMethod.METADATA_EXIF,
                    severity=Severity.MEDIUM,
                    confidence=0.55,
                    description=f"Large metadata field '{key}' ({size} bytes)",
                    evidence=f"first 100 bytes: {val_str[:100]}",
                    metadata={"field": key, "size": size},
                ))
            # Check for base64 or hex-encoded payloads in metadata
            if size > 10 and key not in ('gamma', 'dpi', 'aspect'):
                # Base64 pattern: long string of [A-Za-z0-9+/=]
                if re.search(r'[A-Za-z0-9+/]{20,}={0,2}$', val_str):
                    findings.append(Finding(
                        method=StegMethod.METADATA_EXIF,
                        severity=Severity.HIGH,
                        confidence=0.75,
                        description=f"Metadata field '{key}' contains base64-encoded data",
                        evidence=f"{val_str[:120]}",
                        metadata={"field": key, "encoding": "base64", "size": size},
                    ))
                # Hex pattern: long string of [0-9a-fA-F]
                elif re.search(r'[0-9a-fA-F]{40,}', val_str):
                    findings.append(Finding(
                        method=StegMethod.METADATA_EXIF,
                        severity=Severity.HIGH,
                        confidence=0.70,
                        description=f"Metadata field '{key}' contains hex-encoded data",
                        evidence=f"{val_str[:120]}",
                        metadata={"field": key, "encoding": "hex", "size": size},
                    ))

    return findings


# ─── Steghide Signature Detection ───────────────────────────────────────────

def detect_steghide_signature(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect steghide tool signatures.

    Steghide leaves identifiable patterns in its output files,
    particularly in the way it selects embedding positions using
    a graph-theoretic approach.
    """
    # Steghide uses a specific magic/header pattern in BMP/JPEG files
    # Check for steghide's characteristic even distribution of changes
    # across the file (it uses a permutation based on passphrase)

    if not HAS_PIL or not HAS_NUMPY:
        return []

    # For JPEG: steghide modifies DCT coefficients with a specific pattern
    # For BMP: steghide modifies pixels with graph-based matching
    # The most reliable detection is statistical rather than signature-based

    # Quick heuristic: steghide embeds a header with magic bytes
    # after decryption, so we can't directly detect the header.
    # Instead, we look for the characteristic statistical footprint.

    return []  # Covered by chi-square and RS analysis


# ─── Palette Analysis ────────────────────────────────────────────────────────

def detect_palette_manipulation(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect steganography in palette-based (indexed color) images."""
    if not HAS_PIL:
        return []

    try:
        img = PILImage.open(io.BytesIO(data))
    except Exception:
        return []

    if img.mode != 'P':
        return []

    palette = img.getpalette()
    if not palette:
        return []

    # Check for near-duplicate palette entries (EzStego-style)
    # Steganography in palette images often creates pairs of visually
    # identical colors that differ by 1 in one channel
    findings = []
    n_colors = len(palette) // 3
    near_dupes = 0

    for i in range(n_colors):
        for j in range(i + 1, min(n_colors, i + 5)):  # Check nearby entries
            r1, g1, b1 = palette[i*3], palette[i*3+1], palette[i*3+2]
            r2, g2, b2 = palette[j*3], palette[j*3+1], palette[j*3+2]
            diff = abs(r1-r2) + abs(g1-g2) + abs(b1-b2)
            if 0 < diff <= 3:
                near_dupes += 1

    if near_dupes > 5:
        severity = Severity.HIGH if near_dupes > 20 else Severity.MEDIUM
        confidence = min(0.80, 0.4 + near_dupes * 0.02)

        findings.append(Finding(
            method=StegMethod.PALETTE,
            severity=severity,
            confidence=confidence,
            description=f"{near_dupes} near-duplicate palette entries (possible EzStego/palette steg)",
            evidence=f"{near_dupes} pairs differ by ≤3 across RGB",
            metadata={"near_duplicate_pairs": near_dupes, "total_colors": n_colors},
        ))

    return findings


# ─── Master image scanner ────────────────────────────────────────────────────

def scan_image(data: bytes, filepath: str = "") -> list[Finding]:
    """Run all image steganography detectors on the input data."""
    findings: list[Finding] = []

    # Structural / format checks (fast, no numpy needed)
    findings.extend(detect_trailing_data(data, filepath))
    findings.extend(detect_png_chunks(data, filepath))

    # Statistical analysis (requires numpy + PIL)
    findings.extend(detect_lsb_chi_square(data, filepath))
    findings.extend(detect_lsb_rs_analysis(data, filepath))
    findings.extend(detect_lsb_sample_pairs(data, filepath))
    findings.extend(detect_dct_anomaly(data, filepath))
    findings.extend(detect_bit_plane_anomaly(data, filepath))
    findings.extend(detect_pvd(data, filepath))
    findings.extend(detect_palette_manipulation(data, filepath))
    findings.extend(detect_metadata_hiding(data, filepath))

    return findings
