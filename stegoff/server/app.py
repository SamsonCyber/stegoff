"""
StegOFF API server.

Three deployment modes:
  1. Standalone service    — run this directly, point your app at it
  2. FastAPI middleware     — import StegOffMiddleware into your existing app
  3. Python decorator       — @steg_guard on any function that takes user input

Endpoints:
  POST /scan/file          Upload a file, get scan results
  POST /scan/text          Submit text, get scan results
  POST /guard/file         Upload file, get sanitized file back (or 422 if blocked)
  POST /guard/text         Submit text, get sanitized version back (or 422 if blocked)
  POST /sanitize/image     Upload image, get re-encoded clean image back
  POST /sanitize/audio     Upload audio, get re-encoded clean audio back
  GET  /health             Health check
"""

from __future__ import annotations

import time

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from stegoff.orchestrator import scan, scan_text
from stegoff.sanitizers.text import sanitize_text
from stegoff.sanitizers.image import sanitize_image, sanitize_image_aggressive
from stegoff.sanitizers.audio import sanitize_wav
from stegoff.report import ScanReport, Severity


app = FastAPI(
    title="StegOFF",
    description="Steganography detection, sanitization, and prompt injection guard API",
    version="0.2.0",
)


# ─── Request/Response models ────────────────────────────────────────────────

class TextRequest(BaseModel):
    text: str
    block_on_injection: bool = True
    strip_steg: bool = True


class ScanResult(BaseModel):
    clean: bool
    finding_count: int
    highest_severity: str
    prompt_injection_detected: bool
    findings: list[dict]
    scan_time_ms: float


class GuardTextResponse(BaseModel):
    original_length: int
    clean_length: int
    clean_text: str
    was_dirty: bool
    findings_stripped: int
    prompt_injection_blocked: bool
    categories_stripped: list[str]


# ─── Scan endpoints ─────────────────────────────────────────────────────────

@app.post("/scan/file", response_model=ScanResult)
async def scan_uploaded_file(file: UploadFile = File(...)):
    """
    Scan an uploaded file for steganographic content.

    Returns detailed findings. Does not modify the file.
    Use /guard/file if you want a sanitized version back.
    """
    t0 = time.perf_counter()
    data = await file.read()

    report = scan(data, source=file.filename or "upload")

    # Filenames can carry payloads too
    if file.filename:
        name_report = scan_text(file.filename, source="filename")
        for f in name_report.findings:
            report.add(f)

    elapsed = (time.perf_counter() - t0) * 1000
    return _report_to_result(report, elapsed)


@app.post("/scan/text", response_model=ScanResult)
async def scan_text_input(req: TextRequest):
    """
    Scan text for steganographic content and prompt injection.

    Returns detailed findings. Does not modify the text.
    Use /guard/text if you want sanitized text back.
    """
    t0 = time.perf_counter()
    report = scan_text(req.text, source="api_input")
    elapsed = (time.perf_counter() - t0) * 1000
    return _report_to_result(report, elapsed)


# ─── Guard endpoints (scan + sanitize + block) ──────────────────────────────

@app.post("/guard/text", response_model=GuardTextResponse)
async def guard_text_input(req: TextRequest):
    """
    Sanitize text input before it reaches your AI agent or database.

    Pipeline: scan -> classify injection -> strip steg chars -> return clean text.

    If prompt injection is detected and block_on_injection=True (default),
    returns 422 instead of the sanitized text.
    """
    report = scan_text(req.text, source="guard_input")

    if report.prompt_injection_detected and req.block_on_injection:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "prompt_injection_detected",
                "message": "Input contains steganographically hidden prompt injection",
                "findings": [f.to_dict() for f in report.findings],
            }
        )

    if req.strip_steg:
        clean, result = sanitize_text(req.text)
    else:
        clean = req.text
        from stegoff.sanitizers.text import TextSanitizeResult
        result = TextSanitizeResult(len(req.text), len(req.text), 0, 0, [])

    return GuardTextResponse(
        original_length=len(req.text),
        clean_length=len(clean),
        clean_text=clean,
        was_dirty=not report.clean,
        findings_stripped=report.finding_count,
        prompt_injection_blocked=False,
        categories_stripped=result.categories_stripped,
    )


@app.post("/guard/file")
async def guard_uploaded_file(
    file: UploadFile = File(...),
    block_on_injection: bool = Form(default=True),
    sanitize: bool = Form(default=True),
    jpeg_quality: int = Form(default=85),
):
    """
    Scan an uploaded file. Sanitize it. Return the clean version.

    For text files: strips steg characters, returns clean text.
    For images: re-encodes through PIL (destroys LSB/DCT/PVD payloads),
        randomizes LSB plane, strips metadata. Returns sanitized image bytes.
    For audio (WAV): randomizes sample LSBs, rebuilds from scratch.
        Returns sanitized WAV.

    If prompt injection detected and block_on_injection=True, returns 422.
    """
    data = await file.read()
    report = scan(data, source=file.filename or "upload")

    if report.prompt_injection_detected and block_on_injection:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "prompt_injection_detected",
                "message": "Uploaded file contains steganographic prompt injection",
                "findings": [f.to_dict() for f in report.findings],
            }
        )

    # ── Text files: strip and return ──────────────────────────────
    if report.target_type == "text":
        try:
            text = data.decode('utf-8')
            clean, san_result = sanitize_text(text)
            return JSONResponse({
                "filename": file.filename,
                "type": "text",
                "original_clean": report.clean,
                "finding_count": report.finding_count,
                "sanitized_text": clean,
                "chars_removed": san_result.chars_removed,
                "chars_replaced": san_result.chars_replaced,
                "categories_stripped": san_result.categories_stripped,
            })
        except UnicodeDecodeError:
            pass

    # ── Image files: re-encode to destroy payloads ────────────────
    if report.target_type == "image" and sanitize:
        sanitized_bytes, san_result = sanitize_image(
            data,
            jpeg_quality=jpeg_quality,
            randomize_lsb=True,
            strip_metadata=True,
            strip_trailing=True,
        )

        if san_result.success:
            # Determine content type for response
            fmt = san_result.output_format.upper()
            content_type = {
                "JPEG": "image/jpeg",
                "PNG": "image/png",
                "WEBP": "image/webp",
                "GIF": "image/gif",
                "BMP": "image/bmp",
            }.get(fmt, "application/octet-stream")

            ext = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}.get(fmt, ".bin")
            clean_name = f"sanitized_{file.filename or 'image'}"
            if not clean_name.endswith(ext):
                clean_name = clean_name.rsplit('.', 1)[0] + ext

            return Response(
                content=sanitized_bytes,
                media_type=content_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{clean_name}"',
                    "X-StegOff-Original-Clean": str(report.clean).lower(),
                    "X-StegOff-Finding-Count": str(report.finding_count),
                    "X-StegOff-Operations": "; ".join(san_result.operations),
                    "X-StegOff-Size-Delta": str(san_result.size_delta),
                },
            )

    # ── Audio files (WAV): randomize LSBs, rebuild ────────────────
    if report.target_type == "audio" and sanitize:
        if data[:4] == b'RIFF':
            sanitized_bytes, san_result = sanitize_wav(data)
            if san_result.success:
                clean_name = f"sanitized_{file.filename or 'audio.wav'}"
                return Response(
                    content=sanitized_bytes,
                    media_type="audio/wav",
                    headers={
                        "Content-Disposition": f'attachment; filename="{clean_name}"',
                        "X-StegOff-Original-Clean": str(report.clean).lower(),
                        "X-StegOff-Finding-Count": str(report.finding_count),
                        "X-StegOff-Operations": "; ".join(san_result.operations),
                    },
                )

    # ── Fallback: return scan results for unsupported formats ─────
    return JSONResponse({
        "filename": file.filename,
        "type": report.target_type,
        "clean": report.clean,
        "finding_count": report.finding_count,
        "highest_severity": report.highest_severity.name.lower(),
        "prompt_injection_detected": report.prompt_injection_detected,
        "findings": [f.to_dict() for f in report.findings],
        "recommendation": _recommendation(report),
        "sanitize_supported": False,
        "message": f"Automatic sanitization not yet supported for {report.target_type} files",
    })


# ─── Dedicated sanitize endpoints ───────────────────────────────────────────

@app.post("/sanitize/image")
async def sanitize_image_endpoint(
    file: UploadFile = File(...),
    output_format: str = Form(default=""),
    quality: int = Form(default=85),
    aggressive: bool = Form(default=False),
):
    """
    Re-encode an image to destroy any steganographic payload.

    Returns the sanitized image file directly (binary response).

    Aggressive mode converts to JPEG at reduced quality for maximum
    payload destruction. Standard mode preserves the original format.
    """
    data = await file.read()

    if aggressive:
        sanitized_bytes, result = sanitize_image_aggressive(data, quality=quality)
    else:
        sanitized_bytes, result = sanitize_image(
            data,
            output_format=output_format or None,
            jpeg_quality=quality,
        )

    if not result.success:
        raise HTTPException(status_code=400, detail={
            "error": "sanitization_failed",
            "message": result.error,
        })

    fmt = result.output_format.upper()
    content_type = {
        "JPEG": "image/jpeg", "PNG": "image/png",
        "WEBP": "image/webp",
    }.get(fmt, "application/octet-stream")

    ext = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}.get(fmt, ".bin")
    clean_name = f"clean_{file.filename or 'image'}"
    if not clean_name.lower().endswith(ext.lower()):
        clean_name = clean_name.rsplit('.', 1)[0] + ext

    return Response(
        content=sanitized_bytes,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{clean_name}"',
            "X-StegOff-Operations": "; ".join(result.operations),
            "X-StegOff-Original-Size": str(result.original_size),
            "X-StegOff-Sanitized-Size": str(result.sanitized_size),
        },
    )


@app.post("/sanitize/audio")
async def sanitize_audio_endpoint(file: UploadFile = File(...)):
    """
    Re-encode audio to destroy any steganographic payload.

    Currently supports WAV files. Returns sanitized WAV directly.
    """
    data = await file.read()

    if data[:4] != b'RIFF':
        raise HTTPException(status_code=400, detail={
            "error": "unsupported_format",
            "message": "Only WAV files are currently supported for audio sanitization",
        })

    sanitized_bytes, result = sanitize_wav(data)

    if not result.success:
        raise HTTPException(status_code=400, detail={
            "error": "sanitization_failed",
            "message": result.error,
        })

    clean_name = f"clean_{file.filename or 'audio.wav'}"
    return Response(
        content=sanitized_bytes,
        media_type="audio/wav",
        headers={
            "Content-Disposition": f'attachment; filename="{clean_name}"',
            "X-StegOff-Operations": "; ".join(result.operations),
            "X-StegOff-Original-Size": str(result.original_size),
            "X-StegOff-Sanitized-Size": str(result.sanitized_size),
        },
    )


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _report_to_result(report: ScanReport, elapsed_ms: float) -> ScanResult:
    return ScanResult(
        clean=report.clean,
        finding_count=report.finding_count,
        highest_severity=report.highest_severity.name.lower(),
        prompt_injection_detected=report.prompt_injection_detected,
        findings=[f.to_dict() for f in report.findings],
        scan_time_ms=round(elapsed_ms, 2),
    )


def _recommendation(report: ScanReport) -> str:
    if report.clean:
        return "accept"
    if report.prompt_injection_detected:
        return "reject"
    if report.highest_severity == Severity.CRITICAL:
        return "reject_or_re_encode"
    if report.highest_severity == Severity.HIGH:
        return "quarantine_for_review"
    return "accept_with_warning"
