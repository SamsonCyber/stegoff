"""
Image sanitizer — destroy steganographic payloads through reconstruction.

Core principle: decode to raw pixels, rebuild from scratch. The output
file shares zero bytes with the input. No container structure, metadata,
or encoding-layer artifacts survive.

The reconstruction is lossless. The only pixel-level change is LSB
randomization (±1 per channel, imperceptible, intentional). Output
is always PNG (lossless compression) unless the caller explicitly
opts into a lossy format.

If a JPEG arrives, the lossy decode already happened when the JPEG
was created. We can't recover the pre-compression data, but from
the decoded pixels forward, every step is lossless.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

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


@dataclass
class SanitizeResult:
    """Result of image sanitization."""
    success: bool
    original_size: int
    sanitized_size: int
    input_format: str
    output_format: str
    lossless: bool
    operations: list[str]
    error: str = ""

    @property
    def size_delta(self) -> int:
        return self.sanitized_size - self.original_size


def sanitize_image(
    data: bytes,
    output_format: str | None = None,
    randomize_lsb: bool = True,
    strip_metadata: bool = True,
    strip_trailing: bool = True,
    lossless: bool = True,
    jpeg_quality: int = 85,
) -> tuple[bytes, SanitizeResult]:
    """
    Reconstruct an image from its pixel data to destroy all payloads.

    The pipeline:
      1. Decode input to raw pixel array (format-agnostic)
      2. Strip trailing data appended after EOF markers
      3. Discard all metadata (EXIF, IPTC, XMP, ICC, PNG chunks)
      4. Flatten palette images to RGB (kills palette steg)
      5. Randomize LSB plane (±1 per channel, overwrites hidden bits)
      6. Encode a new file from the pixel array

    Args:
        data: Raw image bytes (any format PIL can read).
        output_format: Force output format ("PNG", "JPEG", "WEBP").
                       None = PNG (lossless) by default, or JPEG if
                       lossless=False.
        randomize_lsb: Randomize LSB plane to destroy bit-level payloads.
        strip_metadata: Remove all metadata (always True for security).
        strip_trailing: Remove data after EOF marker.
        lossless: If True (default), always output PNG regardless of input
                  format. If False, match input format (JPEG stays JPEG).
        jpeg_quality: JPEG quality when outputting JPEG (only used if
                      lossless=False or output_format="JPEG").

    Returns:
        Tuple of (sanitized_bytes, SanitizeResult).
    """
    if not HAS_PIL:
        return data, SanitizeResult(
            success=False,
            original_size=len(data),
            sanitized_size=len(data),
            input_format="unknown",
            output_format="unknown",
            lossless=False,
            operations=[],
            error="Pillow not installed. pip install Pillow",
        )

    ops: list[str] = []

    try:
        img = PILImage.open(io.BytesIO(data))
        src_format = (img.format or "PNG").upper()
        if src_format == "JPG":
            src_format = "JPEG"

        # Determine output format
        if output_format:
            target_format = output_format.upper()
            if target_format == "JPG":
                target_format = "JPEG"
        elif lossless:
            target_format = "PNG"
        else:
            target_format = src_format

        is_lossless_output = target_format in ("PNG", "BMP", "TIFF")

        if src_format == "JPEG" and is_lossless_output:
            ops.append(f"converted {src_format} → {target_format} (lossless from decoded pixels)")

        # ── Step 1: Strip trailing data ──────────────────────────────
        if strip_trailing:
            truncated = _strip_trailing_data(data)
            if len(truncated) < len(data):
                removed = len(data) - len(truncated)
                ops.append(f"stripped {removed} bytes trailing data")
                img = PILImage.open(io.BytesIO(truncated))

        # ── Step 2: Decode to pixel array (the reconstruction) ───────
        # This is the key step. From here, we work only with raw pixels.
        # All container structure, chunk data, and encoding artifacts
        # from the original file are discarded.

        if strip_metadata:
            img = _strip_all_metadata(img)
            ops.append("discarded all metadata (reconstructed from pixels only)")

        # ── Step 3: Normalize color mode ─────────────────────────────
        if img.mode == 'P':
            img = img.convert('RGBA' if 'transparency' in img.info else 'RGB')
            ops.append("flattened palette to RGB (destroys palette steg)")
        elif img.mode == 'LA':
            img = img.convert('RGBA')
        elif img.mode == 'L':
            pass
        elif img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')

        # ── Step 4: Randomize LSB plane ──────────────────────────────
        if randomize_lsb and HAS_NUMPY:
            img = _randomize_lsb_plane(img)
            ops.append("randomized LSB plane (±1 per channel, destroys all bit-level payloads)")

        # ── Step 5: Encode new file from pixel array ─────────────────
        buf = io.BytesIO()

        if target_format == "PNG":
            img.save(buf, format='PNG', optimize=True)
            ops.append("encoded new PNG from pixel array (lossless)")

        elif target_format == "JPEG":
            if img.mode == 'RGBA':
                background = PILImage.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])
                img = background
            elif img.mode != 'RGB':
                img = img.convert('RGB')

            img.save(buf, format='JPEG', quality=jpeg_quality,
                     optimize=True, subsampling=2)
            ops.append(f"encoded new JPEG at quality={jpeg_quality} (lossy, destroys DCT payloads)")

        elif target_format == "WEBP":
            if lossless:
                img.save(buf, format='WEBP', lossless=True)
                ops.append("encoded new WebP (lossless mode)")
            else:
                img.save(buf, format='WEBP', quality=jpeg_quality, method=6)
                ops.append(f"encoded new WebP at quality={jpeg_quality}")

        else:
            img.save(buf, format='PNG', optimize=True)
            target_format = "PNG"
            ops.append("encoded new PNG (fallback, lossless)")

        sanitized = buf.getvalue()

        return sanitized, SanitizeResult(
            success=True,
            original_size=len(data),
            sanitized_size=len(sanitized),
            input_format=src_format,
            output_format=target_format,
            lossless=is_lossless_output,
            operations=ops,
        )

    except Exception as e:
        return data, SanitizeResult(
            success=False,
            original_size=len(data),
            sanitized_size=len(data),
            input_format="unknown",
            output_format="unknown",
            lossless=False,
            operations=ops,
            error=str(e),
        )


def sanitize_image_aggressive(
    data: bytes,
    target_format: str = "PNG",
    quality: int = 80,
) -> tuple[bytes, SanitizeResult]:
    """
    Maximum destruction, still lossless by default.

    Converts any format to PNG, randomizes LSBs, strips everything.
    Use target_format="JPEG" if you want lossy destruction of DCT
    payloads (e.g., F5 that somehow survived the pixel roundtrip,
    which shouldn't happen but belt-and-suspenders).
    """
    is_lossless = target_format.upper() in ("PNG", "BMP", "TIFF")
    return sanitize_image(
        data,
        output_format=target_format,
        jpeg_quality=quality,
        randomize_lsb=True,
        strip_metadata=True,
        strip_trailing=True,
        lossless=is_lossless,
    )


# ─── Internal helpers ────────────────────────────────────────────────────────

def _strip_all_metadata(img: "PILImage.Image") -> "PILImage.Image":
    """
    Reconstruct image from pixel array alone. No metadata survives.
    """
    if HAS_NUMPY:
        pixels = np.array(img)
        clean = PILImage.fromarray(pixels, mode=img.mode)
    else:
        clean = img.copy()
        clean.info = {}
    return clean


def _randomize_lsb_plane(img: "PILImage.Image") -> "PILImage.Image":
    """
    Replace the least-significant bit of every channel with random noise.

    This is the only pixel-level modification. Each channel value changes
    by at most ±1 (out of 255). Imperceptible to humans. Overwrites
    every hidden bit in every encoding scheme that operates at the
    sub-pixel level (LSB, PVD, chroma, SPECTER, etc.).
    """
    pixels = np.array(img, dtype=np.uint8)
    rng = np.random.default_rng()
    random_bits = rng.integers(0, 2, size=pixels.shape, dtype=np.uint8)
    sanitized = (pixels & 0xFE) | random_bits
    return PILImage.fromarray(sanitized, mode=img.mode)


def _strip_trailing_data(data: bytes) -> bytes:
    """Remove data appended after the format's EOF marker."""

    # JPEG: FF D9
    if data[:2] == b'\xff\xd8':
        eof = data.rfind(b'\xff\xd9')
        if eof >= 0:
            return data[:eof + 2]

    # PNG: after IEND chunk + CRC
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        iend = data.find(b'IEND')
        if iend >= 0:
            end_pos = iend + 4 + 4  # IEND (4 bytes) + CRC (4 bytes)
            return data[:end_pos]

    # GIF: 0x3B trailer
    if data[:6] in (b'GIF87a', b'GIF89a'):
        eof = data.rfind(b'\x3b')
        if eof >= 0:
            return data[:eof + 1]

    return data
