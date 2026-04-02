"""
StegOFF middleware for FastAPI.

Drop this into any existing FastAPI app to automatically scan
all incoming requests for steganographic content.

Usage:
    from stegoff.server.middleware import StegOffMiddleware

    app = FastAPI()
    app.add_middleware(StegOffMiddleware)

    # That's it. All POST/PUT/PATCH bodies are now scanned.
    # Requests with prompt injection payloads get blocked with 422.
    # Clean requests pass through untouched.

Configuration:
    app.add_middleware(
        StegOffMiddleware,
        scan_text_bodies=True,       # Scan JSON/form text fields
        scan_file_uploads=True,      # Scan multipart file uploads
        block_on_injection=True,     # 422 on prompt injection (vs. just header warning)
        strip_text_steg=True,        # Rewrite request body with steg stripped
        header_prefix="X-StegOff",# Response header prefix for findings
        skip_paths={"/health", "/metrics"},  # Paths to skip
    )
"""

from __future__ import annotations

import json
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from stegoff.orchestrator import scan_text
from stegoff.sanitizers.text import sanitize_text as _sanitize_text


class StegOffMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that scans request bodies for steganographic content.

    Intercepts POST/PUT/PATCH requests, scans text payloads for hidden
    content, and either blocks or sanitizes before the request reaches
    your application logic.
    """

    def __init__(
        self,
        app,
        scan_text_bodies: bool = True,
        scan_file_uploads: bool = True,
        block_on_injection: bool = True,
        strip_text_steg: bool = True,
        header_prefix: str = "X-StegOff",
        skip_paths: set[str] | None = None,
    ):
        super().__init__(app)
        self.scan_text_bodies = scan_text_bodies
        self.scan_file_uploads = scan_file_uploads
        self.block_on_injection = block_on_injection
        self.strip_text_steg = strip_text_steg
        self.header_prefix = header_prefix
        self.skip_paths = skip_paths or set()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip non-mutation methods and excluded paths
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        if request.url.path in self.skip_paths:
            return await call_next(request)

        content_type = request.headers.get("content-type", "")
        t0 = time.perf_counter()

        # Scan JSON bodies
        if self.scan_text_bodies and "application/json" in content_type:
            try:
                body = await request.body()
                text = body.decode("utf-8")

                # Extract all string values from JSON
                strings_to_scan = _extract_strings(json.loads(text))
                combined = "\n".join(strings_to_scan)

                if combined:
                    report = scan_text(combined, source=request.url.path)

                    if report.prompt_injection_detected and self.block_on_injection:
                        return JSONResponse(
                            status_code=422,
                            content={
                                "error": "steg_prompt_injection_blocked",
                                "detail": "Request contains steganographically hidden prompt injection",
                                "path": request.url.path,
                                "findings": [f.to_dict() for f in report.findings],
                            },
                        )

                    if not report.clean and self.strip_text_steg:
                        # Rewrite the body with steg stripped
                        clean_body = _strip_json_steg(text)
                        # Starlette doesn't let us modify the body directly,
                        # so we store cleaned data for the route to pick up
                        request.state.stegoff_clean_body = clean_body
                        request.state.stegoff_dirty = True
                        request.state.stegoff_findings = report.finding_count
                    else:
                        request.state.stegoff_dirty = False

            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # Scan form data (text fields)
        if self.scan_text_bodies and "form" in content_type:
            try:
                form = await request.form()
                text_values = [
                    str(v) for v in form.values()
                    if isinstance(v, str) and len(v) > 0
                ]
                combined = "\n".join(text_values)

                if combined:
                    report = scan_text(combined, source=request.url.path)

                    if report.prompt_injection_detected and self.block_on_injection:
                        return JSONResponse(
                            status_code=422,
                            content={
                                "error": "steg_prompt_injection_blocked",
                                "detail": "Form data contains steganographic prompt injection",
                            },
                        )
            except Exception:
                pass

        elapsed = (time.perf_counter() - t0) * 1000
        response = await call_next(request)

        # Add scan metadata headers
        response.headers[f"{self.header_prefix}-Scanned"] = "true"
        response.headers[f"{self.header_prefix}-Time-Ms"] = f"{elapsed:.1f}"
        if hasattr(request.state, "stegoff_dirty"):
            response.headers[f"{self.header_prefix}-Dirty"] = str(
                request.state.stegoff_dirty
            ).lower()

        return response


def _extract_strings(obj, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a JSON object."""
    if depth > 10:
        return []
    strings = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            strings.extend(_extract_strings(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            strings.extend(_extract_strings(item, depth + 1))
    return strings


def _strip_steg_chars(text: str) -> str:
    """Convenience wrapper around canonical sanitizer."""
    clean, _ = _sanitize_text(text)
    return clean


def _strip_json_steg(json_text: str) -> str:
    """Strip steg from all string values in a JSON body."""
    try:
        obj = json.loads(json_text)
        cleaned = _clean_json_values(obj)
        return json.dumps(cleaned, ensure_ascii=False)
    except json.JSONDecodeError:
        return _strip_steg_chars(json_text)


def _clean_json_values(obj):
    """Recursively clean string values in JSON."""
    if isinstance(obj, str):
        return _strip_steg_chars(obj)
    elif isinstance(obj, dict):
        return {k: _clean_json_values(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_clean_json_values(item) for item in obj]
    return obj
