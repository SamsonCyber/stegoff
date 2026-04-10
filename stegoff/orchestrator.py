"""
Orchestrator — routes files to the right detectors and aggregates results.
"""

from __future__ import annotations

import base64
import codecs
import html
import json
import mimetypes
import re
from pathlib import Path

from stegoff.report import Finding, ScanReport, Severity, StegMethod
from stegoff.detectors.text import scan_text_all
from stegoff.detectors.image import scan_image
from stegoff.detectors.binary import scan_binary
from stegoff.detectors.audio import scan_audio
from stegoff.detectors.prompt_injection import scan_payload_for_injection, scan_raw_text_for_injection
from stegoff.detectors.llm import detect_semantic_steg


# ── L2 detection: local transformer with Haiku fallback ────────────
_transformer_detector = None
_transformer_load_attempted = False


def _get_transformer_detector():
    """Lazy-load the transformer detector once."""
    global _transformer_detector, _transformer_load_attempted
    if _transformer_load_attempted:
        return _transformer_detector
    _transformer_load_attempted = True
    try:
        from stegoff.ml.transformer_classifier import TransformerDetector
        _transformer_detector = TransformerDetector.load()
    except Exception:
        _transformer_detector = None
    return _transformer_detector


def _run_l2_detection(text: str, api_key: str | None = None) -> list:
    """L2 semantic detection: local transformer if available, Haiku fallback.

    The fine-tuned DistilBERT catches all 18 red team attack categories
    including JSON tool calls, complexity camouflage, double negation,
    and opaque directives. Haiku is only used when the transformer model
    isn't installed.
    """
    detector = _get_transformer_detector()
    if detector is not None:
        return detector.detect(text)
    return detect_semantic_steg(text, api_key=api_key)


# MIME type to detector routing
IMAGE_MIMES = {'image/png', 'image/jpeg', 'image/gif', 'image/bmp', 'image/tiff', 'image/webp'}
TEXT_MIMES = {'text/plain', 'text/html', 'text/csv', 'text/markdown', 'text/xml',
              'application/json', 'application/xml', 'application/javascript',
              'text/x-python', 'text/x-shellscript', 'text/x-c', 'text/css',
              'application/x-yaml', 'application/toml', 'text/x-tex',
              'application/sql', 'text/x-ini', 'application/x-sh'}

# File extensions that should be treated as text regardless of MIME detection
_TEXT_EXTENSIONS = {
    '.txt', '.py', '.js', '.ts', '.css', '.html', '.htm', '.xml', '.json',
    '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.sh', '.bash',
    '.sql', '.tex', '.md', '.rst', '.csv', '.tsv', '.c', '.h', '.cpp',
    '.java', '.rb', '.go', '.rs', '.swift', '.kt', '.r', '.lua',
    '.svg', '.rtf', '.pem', '.hexdump', '.pcap', '.mid', '.midi',
    '.sqlite', '.db',
}
PDF_MIMES = {'application/pdf'}
AUDIO_MIMES = {'audio/wav', 'audio/mpeg', 'audio/flac', 'audio/ogg', 'audio/x-wav',
               'audio/aiff', 'audio/x-aiff', 'audio/basic'}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB


def _multi_decode(text: str, max_depth: int = 3) -> list[str]:
    """Try base64, ROT13, hex decoding iteratively. Return all decoded variants."""
    variants = []
    current = text
    for _ in range(max_depth):
        # Try base64
        try:
            decoded = base64.b64decode(current).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 5:
                variants.append(decoded)
                current = decoded
                continue
        except Exception:
            pass
        # Try ROT13 then base64
        rot = codecs.decode(current, 'rot_13')
        if rot != current:
            try:
                decoded = base64.b64decode(rot).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 5:
                    variants.append(decoded)
            except Exception:
                pass
        break
    return variants


def scan_text(text: str, source: str = "<text>", use_llm: bool = False,
              api_key: str | None = None) -> ScanReport:
    """Scan a text string for steganographic content.

    Args:
        text: Text to scan.
        source: Label for the scan report.
        use_llm: If True, run LLM-based semantic analysis as final pass.
                 Requires anthropic SDK and API key.
        api_key: Anthropic API key for LLM detector. Falls back to env/file.
    """
    report = ScanReport(target=source, target_type="text")

    # HTML entity decoding: flag numeric entities as potential encoding channel
    decoded_text = html.unescape(text)
    numeric_entities = re.findall(r'&#\d+;', text)
    if len(numeric_entities) >= 3:
        decoded_chars = html.unescape(''.join(numeric_entities))
        report.add(Finding(
            method=StegMethod.HTML_ENTITY,
            severity=Severity.HIGH,
            confidence=0.9,
            description=f"Found {len(numeric_entities)} numeric HTML entities encoding: '{decoded_chars[:50]}'",
            metadata={"entity_count": len(numeric_entities), "decoded": decoded_chars[:100]},
        ))
    if decoded_text != text:
        extra_findings = scan_text_all(decoded_text)
        for f in extra_findings:
            f.metadata["decoded_from"] = "html_entities"
            report.add(f)

    # Multi-pass encoding detection: find base64-looking strings and decode them
    # Only flag if decoded content contains injection patterns (avoids FP on JWTs etc)
    b64_candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for candidate in b64_candidates[:10]:
        variants = _multi_decode(candidate)
        for variant in variants:
            injection_hits = scan_payload_for_injection(variant, source="multi_decode")
            if injection_hits:
                report.add(Finding(
                    method=StegMethod.MULTI_ENCODING,
                    severity=Severity.HIGH,
                    confidence=0.80,
                    description=f"Multi-layer encoded injection: '{variant[:60]}'",
                    decoded_payload=variant[:200],
                    metadata={"encoding_layers": len(variants), "original": candidate[:40]},
                ))
                for inj in injection_hits:
                    report.add(inj)

    # Run all text steg detectors
    findings = scan_text_all(text)

    # For any decoded payloads, check for prompt injection
    for finding in findings:
        report.add(finding)
        if finding.decoded_payload and len(finding.decoded_payload) > 3:
            injection_findings = scan_payload_for_injection(
                finding.decoded_payload,
                source=f"decoded from {finding.method.value}"
            )
            for inj in injection_findings:
                report.add(inj)

    # Structural analysis: JSON, comments, encoded content
    stripped = text.strip()
    if stripped.startswith('{') or stripped.startswith('['):
        for f in _scan_json_structure(text, source):
            report.add(f)
    for f in _scan_comment_steg(text, source):
        report.add(f)
    for f in _scan_encoded_content(text, source):
        report.add(f)

    # Direct prompt injection scan on raw text (catches leetspeak,
    # synonym substitution, and other obfuscated injections).
    # Uses the safe subset of patterns that won't false-positive on normal text.
    injection_hits = scan_raw_text_for_injection(text, source="raw_text")
    for f in injection_hits:
        report.add(f)

    # L2 semantic analysis (opt-in, catches synonym/structure encoding)
    # Prefer local transformer if available, fall back to Haiku API
    if use_llm and report.clean:
        l2_findings = _run_l2_detection(text, api_key)
        for f in l2_findings:
            report.add(f)

    return report


def scan_file(filepath: str | Path, use_llm: bool = False,
              api_key: str | None = None) -> ScanReport:
    """Scan a file for steganographic content."""
    path = Path(filepath)
    if not path.exists():
        report = ScanReport(target=str(path), target_type="unknown")
        report.add(Finding(
            method=StegMethod.TRAILING_DATA,
            severity=Severity.LOW,
            confidence=0.0,
            description=f"File not found: {path}",
        ))
        return report

    if path.stat().st_size > MAX_FILE_SIZE:
        report = ScanReport(target=str(path), target_type="file")
        report.add(Finding(
            method=StegMethod.TRAILING_DATA,
            severity=Severity.CRITICAL,
            confidence=1.0,
            description=f"File exceeds maximum size ({path.stat().st_size} > {MAX_FILE_SIZE})",
            metadata={"detector": "size_guard"},
        ))
        return report

    data = path.read_bytes()
    mime_type, _ = mimetypes.guess_type(str(path))
    mime_type = mime_type or _guess_mime_from_bytes(data)

    report = ScanReport(target=str(path), target_type=_classify_type(mime_type))

    # Scan filename for encoded payloads (base64, hex in the name itself)
    fname = path.stem
    if len(fname) > 20:
        for variant in _multi_decode(fname.replace('_', '+').replace('-', '/')):
            inj = scan_payload_for_injection(variant, source="filename")
            for f in inj:
                report.add(f)
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', fname):
            report.add(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.60,
                description=f"Filename contains base64-like encoded data ({len(fname)} chars)",
                evidence=f"Filename: {fname[:80]}",
                metadata={"technique": "filename_steg"},
            ))

    # Always run binary/structural checks
    findings = scan_binary(data, str(path))
    for f in findings:
        report.add(f)

    # Route to type-specific detectors
    # Use BOTH MIME type and magic bytes to prevent content-type mismatch bypass
    magic_mime = _guess_mime_from_bytes(data)
    is_image = (mime_type in IMAGE_MIMES or _classify_type(mime_type) == "image"
                or magic_mime in IMAGE_MIMES)
    if is_image:
        for f in scan_image(data, str(path)):
            report.add(f)

    is_text = (mime_type in TEXT_MIMES or _classify_type(mime_type) == "text"
               or path.suffix.lower() in _TEXT_EXTENSIONS)
    if is_text:
        text = _decode_text(data)
        if text is not None:
            text_findings = scan_text_all(text)
            for f in text_findings:
                report.add(f)
                if f.decoded_payload and len(f.decoded_payload) > 3:
                    for inj in scan_payload_for_injection(f.decoded_payload):
                        report.add(inj)
            # JSON structural analysis
            if mime_type == 'application/json' or str(path).endswith('.json'):
                for f in _scan_json_structure(text, str(path)):
                    report.add(f)
            # Comment/markup steg in code and config files
            for f in _scan_comment_steg(text, str(path)):
                report.add(f)
            # Encoded content patterns (base32, hex dumps, morse, punycode, etc.)
            for f in _scan_encoded_content(text, str(path)):
                report.add(f)

    is_audio = (mime_type in AUDIO_MIMES or _classify_type(mime_type) == "audio"
                or magic_mime in AUDIO_MIMES)
    if is_audio:
        for f in scan_audio(data, str(path)):
            report.add(f)

    if mime_type in PDF_MIMES:
        pass  # PDF steg already handled by scan_binary

    # Check filesystem extended attributes (Linux/macOS only)
    import os as _os
    if hasattr(_os, 'listxattr'):
        try:
            xattrs = _os.listxattr(str(path))
            for attr in xattrs:
                val = _os.getxattr(str(path), attr)
                if len(val) > 5:
                    # Check for suspicious attribute names
                    attr_lower = attr.lower()
                    suspicious_name = any(kw in attr_lower for kw in (
                        'steg', 'hidden', 'secret', 'payload', 'covert', 'inject',
                    ))
                    # Check for readable text in attribute value
                    try:
                        decoded = val.decode('utf-8', errors='replace')
                        readable = sum(1 for c in decoded if c.isprintable()) / max(len(decoded), 1)
                    except Exception:
                        decoded = ""
                        readable = 0

                    if suspicious_name or (readable > 0.7 and len(val) > 15):
                        report.add(Finding(
                            method=StegMethod.EMBEDDED_FILE,
                            severity=Severity.HIGH,
                            confidence=0.85,
                            description=f"Filesystem extended attribute '{attr}' contains hidden data ({len(val)} bytes)",
                            evidence=f"{attr} = {decoded[:150]}" if decoded else f"{attr} = {val[:50].hex()}",
                            decoded_payload=decoded[:500] if readable > 0.5 else "",
                            metadata={"xattr": attr, "size": len(val)},
                        ))
                        # Scan xattr content for prompt injection
                        if decoded and len(decoded) > 10:
                            for inj in scan_payload_for_injection(decoded, source=f"xattr:{attr}"):
                                report.add(inj)
        except OSError:
            pass  # Filesystem doesn't support xattrs

    # Check for prompt injection in any decoded payloads from image/binary scans
    for finding in list(report.findings):
        if finding.decoded_payload and finding.method != StegMethod.PROMPT_INJECTION:
            if len(finding.decoded_payload) > 3:
                for inj in scan_payload_for_injection(finding.decoded_payload):
                    if inj not in report.findings:
                        report.add(inj)

    return report


def scan(target: str | Path | bytes, source: str = "<input>",
         use_llm: bool = False, api_key: str | None = None) -> ScanReport:
    """
    Universal scan entry point.

    Accepts: file path (str/Path), raw bytes, or text string.
    Auto-detects the input type and routes accordingly.
    """
    if isinstance(target, Path):
        return scan_file(target, use_llm=use_llm, api_key=api_key)

    if isinstance(target, bytes):
        # Treat as binary data
        report = ScanReport(target=source, target_type="binary")
        for f in scan_binary(target, source):
            report.add(f)
        # Try as image
        for f in scan_image(target, source):
            report.add(f)
        # Try as audio
        for f in scan_audio(target, source):
            report.add(f)
        # Try decoding as text (multiple encodings)
        text = _decode_text(target)
        if text is not None:
            for f in scan_text_all(text):
                report.add(f)
                if f.decoded_payload and len(f.decoded_payload) > 3:
                    for inj in scan_payload_for_injection(f.decoded_payload):
                        report.add(inj)
        return report

    if isinstance(target, str):
        # Check if it's a file path
        path = Path(target)
        if path.exists() and path.is_file():
            return scan_file(path, use_llm=use_llm, api_key=api_key)
        # Treat as text
        return scan_text(target, source, use_llm=use_llm, api_key=api_key)

    raise TypeError(f"Unsupported target type: {type(target)}")


def _decode_text(data: bytes) -> str | None:
    """Decode bytes to text, trying multiple encodings.
    Handles UTF-8, UTF-16 (with BOM), UTF-16LE/BE, and Latin-1 fallback."""
    # UTF-8 BOM
    if data[:3] == b'\xef\xbb\xbf':
        try:
            return data[3:].decode('utf-8')
        except UnicodeDecodeError:
            pass
    # UTF-16 BOM (LE or BE)
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            return data.decode('utf-16')
        except UnicodeDecodeError:
            pass
    # UTF-8 (most common)
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        pass
    # UTF-16 without BOM (heuristic: lots of null bytes)
    null_ratio = data[:200].count(b'\x00') / max(len(data[:200]), 1)
    if null_ratio > 0.3:
        for enc in ('utf-16-le', 'utf-16-be'):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
    # Latin-1 fallback (never fails, covers corrupted UTF-8)
    return data.decode('latin-1')


def _scan_encoded_content(text: str, source: str = "") -> list[Finding]:
    """Detect encoded payloads in text: base32, hex dumps, morse, punycode, PEM certs."""
    findings = []

    # Base32 encoding (uppercase A-Z, 2-7, padding =)
    b32_matches = re.findall(r'[A-Z2-7]{20,}={0,6}', text)
    if b32_matches:
        longest = max(b32_matches, key=len)
        if len(longest) >= 24:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.65,
                description=f"Base32-encoded data found ({len(longest)} chars)",
                evidence=f"{longest[:100]}",
                metadata={"encoding": "base32", "length": len(longest)},
            ))

    # Hex dump pattern (lines of hex bytes like "a3 1c 06 bd 46 3e")
    hex_lines = re.findall(r'(?:^|\n)\s*[0-9a-f]{8}\s+(?:[0-9a-f]{2}\s+){8,}', text, re.IGNORECASE)
    if len(hex_lines) >= 3:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.65,
            description=f"Hex dump with {len(hex_lines)} lines (possible embedded binary data)",
            evidence=f"First line: {hex_lines[0].strip()[:80]}",
            metadata={"hex_lines": len(hex_lines)},
        ))

    # Morse code pattern (sequences of . and - separated by spaces/slashes)
    morse_pattern = re.findall(r'(?:[.\-]{1,6}\s+){5,}', text)
    if morse_pattern:
        total_morse_chars = sum(len(m.split()) for m in morse_pattern)
        if total_morse_chars >= 20:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.60,
                description=f"Morse code pattern detected ({total_morse_chars} symbols)",
                evidence=f"Pattern: {morse_pattern[0][:80]}",
                metadata={"morse_symbols": total_morse_chars},
            ))

    # Punycode/IDN domains (xn-- prefix)
    punycode_domains = re.findall(r'xn--[a-z0-9\-]+\.', text, re.IGNORECASE)
    if len(punycode_domains) >= 3:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.65,
            description=f"{len(punycode_domains)} Punycode/IDN domains (data in internationalized labels)",
            evidence=f"Domains: {', '.join(punycode_domains[:5])}",
            metadata={"punycode_count": len(punycode_domains)},
        ))

    # PEM certificate with suspicious content
    if '-----BEGIN' in text:
        pem_blocks = re.findall(r'-----BEGIN (.+?)-----(.+?)-----END', text, re.DOTALL)
        for block_type, block_data in pem_blocks:
            clean = block_data.replace('\n', '').replace('\r', '').strip()
            if any(kw in clean.lower() for kw in ('steg', 'hidden', 'payload', 'secret')):
                findings.append(Finding(
                    method=StegMethod.EMBEDDED_FILE,
                    severity=Severity.HIGH,
                    confidence=0.80,
                    description=f"PEM {block_type} block contains suspicious content",
                    evidence="Keywords found in certificate data",
                    metadata={"block_type": block_type},
                ))
                break

    # QR code text representation (dense block character patterns)
    qr_chars = text.count('█') + text.count('▄') + text.count('▀')
    if qr_chars > 50:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.60,
            description=f"QR code pattern detected ({qr_chars} block characters)",
            evidence="Dense Unicode block character matrix found",
            metadata={"block_chars": qr_chars},
        ))

    # Capitalization encoding: check for unnatural case patterns in prose
    # Skip code-like content (SQL, programming languages have uppercase keywords)
    code_indicators = {'SELECT', 'FROM', 'WHERE', 'CREATE', 'INSERT', 'UPDATE', 'DELETE',
                       'TABLE', 'INDEX', 'VIEW', 'BEGIN', 'END', 'FUNCTION', 'RETURN',
                       'IF', 'ELSE', 'WHILE', 'FOR', 'CLASS', 'DEF', 'IMPORT', 'VAR',
                       'CONST', 'LET', 'PUBLIC', 'PRIVATE', 'VOID', 'INT', 'STRING'}
    words = text.split()
    code_word_count = sum(1 for w in words if w.rstrip('();,') in code_indicators)
    is_code = code_word_count > 3

    if len(words) > 30 and not is_code:
        mid_caps = 0
        for i, word in enumerate(words[1:], 1):
            if word[0:1].isupper() and words[i-1][-1:] not in '.!?:':
                mid_caps += 1
        cap_ratio = mid_caps / len(words)
        if cap_ratio > 0.08 and mid_caps > 10:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.60,
                description=f"Unusual capitalization: {mid_caps}/{len(words)} words ({cap_ratio:.0%}) capitalized mid-sentence",
                evidence="May encode bits in case choices",
                metadata={"mid_caps": mid_caps, "total_words": len(words), "ratio": round(cap_ratio, 3)},
            ))

    # Deliberate misspelling pattern detection
    # Common misspellings that are steg signals: words that have known correct forms
    common_misspellings = {
        'apparantly': 'apparently', 'definately': 'definitely', 'occured': 'occurred',
        'seperate': 'separate', 'recieve': 'receive', 'untill': 'until',
        'goverment': 'government', 'begining': 'beginning', 'occassion': 'occasion',
        'neccessary': 'necessary', 'adress': 'address', 'accomodate': 'accommodate',
        'calender': 'calendar', 'concious': 'conscious', 'embarass': 'embarrass',
        'existance': 'existence', 'foriegn': 'foreign', 'gaurante': 'guarantee',
        'harrass': 'harass', 'independant': 'independent', 'judgement': 'judgment',
        'knowlege': 'knowledge', 'liason': 'liaison', 'manuever': 'maneuver',
        'millenium': 'millennium', 'noticable': 'noticeable', 'occurence': 'occurrence',
        'parliment': 'parliament', 'persistant': 'persistent', 'posession': 'possession',
        'privelege': 'privilege', 'publically': 'publicly', 'recomend': 'recommend',
        'refering': 'referring', 'relevent': 'relevant', 'resistence': 'resistance',
        'responsable': 'responsible', 'succesful': 'successful', 'suprise': 'surprise',
        'tommorow': 'tomorrow', 'tyrany': 'tyranny', 'wierd': 'weird',
    }
    misspelled = []
    text_lower = text.lower()
    for wrong, correct in common_misspellings.items():
        if wrong in text_lower:
            misspelled.append(wrong)
    if len(misspelled) >= 3:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.55,
            description=f"{len(misspelled)} deliberate misspellings detected (possible encoding)",
            evidence=f"Misspelled: {', '.join(misspelled[:10])}",
            metadata={"misspelled": misspelled},
        ))

    # Sentence length encoding: check if sentence lengths form a pattern
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
    if len(sentences) >= 8:
        lengths = [len(s.split()) for s in sentences]
        # Check if odd/even pattern could encode bits
        parities = [n % 2 for n in lengths]
        # High alternation rate suggests encoding
        alternations = sum(1 for i in range(1, len(parities)) if parities[i] != parities[i-1])
        alt_rate = alternations / max(len(parities) - 1, 1)
        # Check for genuine alternation (not just repeated content)
        unique_lengths = len(set(lengths))
        if alt_rate > 0.8 and len(sentences) >= 10 and unique_lengths >= len(sentences) // 2:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.55,
                description=f"Sentence lengths show high odd/even alternation ({alt_rate:.0%}), possible encoding",
                evidence=f"Lengths: {lengths[:15]}",
                metadata={"alternation_rate": round(alt_rate, 3), "sentence_count": len(sentences)},
            ))

    # HTML data-* attributes with numeric values (byte encoding)
    data_attrs = re.findall(r'data-[a-z0-9-]+\s*=\s*"(\d{1,3})"', text, re.IGNORECASE)
    if len(data_attrs) >= 5:
        vals = [int(v) for v in data_attrs if v.isdigit()]
        ascii_count = sum(1 for v in vals if 32 <= v <= 126)
        if ascii_count / max(len(vals), 1) > 0.6:
            try:
                decoded = bytes(v & 0xFF for v in vals if 0 <= v <= 255).decode('ascii', errors='replace')
                printable = sum(1 for c in decoded if c.isprintable())
                if printable / max(len(decoded), 1) > 0.5:
                    findings.append(Finding(
                        method=StegMethod.EMBEDDED_FILE,
                        severity=Severity.HIGH,
                        confidence=0.70,
                        description=f"HTML data attributes contain {len(data_attrs)} numeric values that decode to ASCII",
                        evidence=f"Decoded: {decoded[:100]}",
                        decoded_payload=decoded,
                        metadata={"attr_count": len(data_attrs)},
                    ))
            except Exception:
                pass

    # CSS custom properties with numeric values (byte encoding)
    css_vars = re.findall(r'--[a-z0-9-]+\s*:\s*(\d{1,3})\s*;', text, re.IGNORECASE)
    if len(css_vars) >= 5:
        vals = [int(v) for v in css_vars if v.isdigit()]
        ascii_count = sum(1 for v in vals if 32 <= v <= 126)
        if ascii_count / max(len(vals), 1) > 0.6:
            try:
                decoded = bytes(v & 0xFF for v in vals if 0 <= v <= 255).decode('ascii', errors='replace')
                printable = sum(1 for c in decoded if c.isprintable())
                if printable / max(len(decoded), 1) > 0.5:
                    findings.append(Finding(
                        method=StegMethod.EMBEDDED_FILE,
                        severity=Severity.HIGH,
                        confidence=0.70,
                        description=f"CSS custom properties contain {len(css_vars)} numeric values that decode to ASCII",
                        evidence=f"Decoded: {decoded[:100]}",
                        decoded_payload=decoded,
                        metadata={"var_count": len(css_vars)},
                    ))
            except Exception:
                pass

    # EXIF GPS coordinate precision encoding (8+ decimal places)
    gps_coords = re.findall(r'(?:lat|long|gps|coord)[^0-9]{0,20}(-?\d+\.\d{8,})', text, re.IGNORECASE)
    if len(gps_coords) >= 2:
        findings.append(Finding(
            method=StegMethod.METADATA_EXIF,
            severity=Severity.MEDIUM,
            confidence=0.55,
            description=f"{len(gps_coords)} GPS coordinates with unusual precision (8+ decimal places)",
            evidence=f"Coordinates: {', '.join(gps_coords[:4])}",
            metadata={"coord_count": len(gps_coords)},
        ))

    return findings


def _scan_comment_steg(text: str, source: str = "") -> list[Finding]:
    """Detect steganographic payloads hidden in code comments and markup."""


    findings = []

    # Compile patterns used for HTML attribute and comment scanning
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    hex_pattern = re.compile(r'(?:0x)?[0-9a-fA-F]{2}(?:[,\s]+(?:0x)?[0-9a-fA-F]{2}){7,}')
    steg_keywords = re.compile(
        r'(?:hidden|secret|payload|steg|encoded|inject|decode|covert|embed)',
        re.IGNORECASE,
    )

    # Extract comments from various languages
    comments = []
    # Single-line: # // % -- ;
    # Require comment markers at line start or after whitespace (not inside URLs like https://)
    for m in re.finditer(r'(?:^|(?<=\s))(?:#|//|--|;)\s*(.*?)$', text, re.MULTILINE):
        comments.append(m.group(1).strip())
    # % comments only in TeX-like context (line must start with %)
    for m in re.finditer(r'^\s*%\s*(.*?)$', text, re.MULTILINE):
        comments.append(m.group(1).strip())
    # Block comments: /* ... */ and <!-- ... -->
    for m in re.finditer(r'/\*(.+?)\*/', text, re.DOTALL):
        comments.append(m.group(1).strip())
    for m in re.finditer(r'<!--(.+?)-->', text, re.DOTALL):
        comments.append(m.group(1).strip())

    # HTML event handler attributes — only flag if they contain encoded data or steg keywords
    for m in re.finditer(r'\bon\w+\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE):
        val = m.group(1).strip()
        if len(val) > 30 and (b64_pattern.search(val) or hex_pattern.search(val) or steg_keywords.search(val)):
            comments.append(val)

    # XML/HTML hidden elements — only flag when steg-specific keywords appear
    # (not just "hidden" which is common in normal CSS/HTML)
    for m in re.finditer(r'(?:display\s*:\s*none|visibility\s*:\s*hidden|type\s*=\s*["\']hidden["\'])', text, re.IGNORECASE):
        start = max(0, m.start() - 200)
        end = min(len(text), m.end() + 200)
        context = text[start:end]
        if any(kw in context.lower() for kw in ('payload', 'secret', 'steg', 'encoded')):
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.80,
                description="Hidden HTML element contains suspicious content",
                evidence=context[:200],
                metadata={"technique": "hidden_element"},
            ))

    # XML entity definitions that could hide data
    for m in re.finditer(r'<!ENTITY\s+\w+\s+["\'](.+?)["\']', text, re.DOTALL):
        val = m.group(1)
        if len(val) > 20:
            comments.append(val)

    if not comments:
        return findings

    b64_hits = 0
    hex_hits = 0
    keyword_hits = 0

    for comment in comments:
        if b64_pattern.search(comment):
            b64_hits += 1
        if hex_pattern.search(comment):
            hex_hits += 1
        if steg_keywords.search(comment):
            keyword_hits += 1

    # Check for ROT13/Caesar obfuscation: decode and check for injection patterns
    rot13_hits = 0

    for comment in comments:
        if len(comment) > 15:
            try:
                decoded_rot = codecs.decode(comment, 'rot_13')
                if any(pat in decoded_rot.lower() for pat in (
                    'ignore', 'instruction', 'system prompt', 'override',
                    'jailbreak', 'admin', 'execute', 'password', 'secret',
                )):
                    rot13_hits += 1
            except Exception:
                pass

    if rot13_hits > 0:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.HIGH,
            confidence=0.80,
            description=f"ROT13-obfuscated suspicious content in {rot13_hits} comment(s)",
            evidence="Decoded comments contain injection-like patterns",
            metadata={"rot13_comments": rot13_hits},
        ))

    if b64_hits > 0:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.HIGH,
            confidence=0.75,
            description=f"Base64-encoded data found in {b64_hits} code comment(s)",
            evidence=f"Detected in comments of {source}",
            metadata={"b64_comments": b64_hits},
        ))
    if hex_hits > 0:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.65,
            description=f"Hex byte sequences found in {hex_hits} code comment(s)",
            evidence=f"Detected in comments of {source}",
            metadata={"hex_comments": hex_hits},
        ))
    if keyword_hits > 0 and (b64_hits > 0 or hex_hits > 0):
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.HIGH,
            confidence=0.85,
            description="Steganography keywords + encoded data in comments",
            evidence=f"{keyword_hits} keyword(s) alongside encoded content",
            metadata={"keyword_comments": keyword_hits},
        ))

    return findings


def _scan_json_structure(text: str, source: str = "") -> list[Finding]:
    """Scan JSON for steganographic payloads hidden in field values."""



    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    findings = []
    suspicious_keys = {'payload', 'hidden', 'secret', 'steg', 'encoded',
                       'payload_b64', 'payload_hex', 'payload_direct',
                       'data', 'message', 'inject'}

    def _walk(node, path="$", depth=0, max_depth=20):
        if depth > max_depth:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                _check_kv(key, val, f"{path}.{key}")
                _walk(val, f"{path}.{key}", depth + 1, max_depth)
        elif isinstance(node, list):
            # Check for numeric arrays that could be byte-encoded payloads
            if len(node) >= 10 and all(isinstance(x, (int, float)) for x in node):
                _check_numeric_array(node, path)
            for i, item in enumerate(node):
                _walk(item, f"{path}[{i}]", depth + 1, max_depth)

    def _check_numeric_array(arr, path):
        """Check if a numeric array encodes ASCII text as byte values."""
        # Integer arrays where values are in printable ASCII range (32-126)
        int_vals = [int(round(x)) for x in arr]
        ascii_count = sum(1 for v in int_vals if 32 <= v <= 126)
        ratio = ascii_count / len(int_vals)
        if ratio > 0.7 and len(int_vals) >= 10:
            # Try decoding as ASCII
            try:
                decoded = bytes(v & 0xFF for v in int_vals if 0 <= v <= 255).decode('ascii', errors='replace')
                printable = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
                if printable / max(len(decoded), 1) > 0.6:
                    findings.append(Finding(
                        method=StegMethod.EMBEDDED_FILE,
                        severity=Severity.HIGH,
                        confidence=0.75,
                        description=f"Numeric array at {path} decodes to readable ASCII text",
                        evidence=f"Decoded: {decoded[:150]}",
                        decoded_payload=decoded[:500],
                        location=path,
                        metadata={"array_length": len(arr), "ascii_ratio": round(ratio, 2)},
                    ))
            except Exception:
                pass

        # Float arrays that could be scaled byte values (e.g., 7.2 = 72)
        if all(isinstance(x, float) for x in arr) and len(arr) >= 10:
            for scale in (10.0, 100.0, 1.0):
                scaled = [int(round(x * scale)) for x in arr]
                ascii_count = sum(1 for v in scaled if 32 <= v <= 126)
                if ascii_count / len(scaled) > 0.7:
                    try:
                        decoded = bytes(v & 0xFF for v in scaled if 0 <= v <= 255).decode('ascii', errors='replace')
                        printable = sum(1 for c in decoded if c.isprintable())
                        if printable / max(len(decoded), 1) > 0.6:
                            findings.append(Finding(
                                method=StegMethod.EMBEDDED_FILE,
                                severity=Severity.MEDIUM,
                                confidence=0.60,
                                description=f"Float array at {path} may encode text (scale={scale}x)",
                                evidence=f"Decoded: {decoded[:150]}",
                                decoded_payload=decoded[:500],
                                location=path,
                                metadata={"array_length": len(arr), "scale": scale},
                            ))
                            break
                    except Exception:
                        pass

    def _check_kv(key, val, path):
        key_lower = key.lower().replace('-', '_').replace(' ', '_')
        if not isinstance(val, str) or len(val) < 5:
            return
        # Suspicious key names
        if any(s in key_lower for s in suspicious_keys):
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.80,
                description=f"JSON field '{key}' has suspicious name suggesting hidden payload",
                evidence=f"{path} = {val[:150]}",
                location=path,
                decoded_payload=val[:500],
                metadata={"key": key, "path": path},
            ))
            return
        # Base64 pattern in values
        if re.fullmatch(r'[A-Za-z0-9+/]{20,}={0,2}', val):
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.65,
                description=f"JSON field '{key}' contains base64-encoded data",
                evidence=f"{path} = {val[:150]}",
                location=path,
                metadata={"key": key, "encoding": "base64"},
            ))
        # Long hex string
        elif re.fullmatch(r'[0-9a-fA-F]{40,}', val):
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.60,
                description=f"JSON field '{key}' contains hex-encoded data",
                evidence=f"{path} = {val[:150]}",
                location=path,
                metadata={"key": key, "encoding": "hex"},
            ))

    _walk(obj)
    return findings


def _guess_mime_from_bytes(data: bytes) -> str:
    """Guess MIME type from file header bytes."""
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    if data[:2] == b'\xff\xd8':
        return 'image/jpeg'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    if data[:2] == b'BM':
        return 'image/bmp'
    if data[:4] == b'RIFF':
        # RIFF can be WAV or WebP
        if len(data) > 8 and data[8:12] == b'WEBP':
            return 'image/webp'
        return 'audio/wav'
    if data[:4] == b'FORM':
        if len(data) > 8 and data[8:12] in (b'AIFF', b'AIFC'):
            return 'audio/aiff'
    if data[:4] == b'.snd':
        return 'audio/basic'
    if data[:4] == b'%PDF':
        return 'application/pdf'
    if data[:3] == b'ID3' or data[:2] in (b'\xff\xfb', b'\xff\xf3'):
        return 'audio/mpeg'
    if data[:4] == b'fLaC':
        return 'audio/flac'
    if data[:2] == b'\x1f\x8b':
        return 'application/gzip'
    if data[:4] == b'PK\x03\x04':
        return 'application/zip'
    if data[:4] == b'MThd':
        return 'audio/midi'
    if data[:15] == b'SQLite format 3':
        return 'application/x-sqlite3'
    if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return 'application/vnd.tcpdump.pcap'
    if data[:5] == b'{\\rtf':
        return 'application/rtf'
    # Try text
    try:
        data[:1000].decode('utf-8')
        return 'text/plain'
    except UnicodeDecodeError:
        return 'application/octet-stream'


def _classify_type(mime: str | None) -> str:
    """Classify MIME into our type categories."""
    if not mime:
        return "unknown"
    if mime in IMAGE_MIMES or mime.startswith('image/'):
        return "image"
    if mime in TEXT_MIMES or mime.startswith('text/'):
        return "text"
    if mime in PDF_MIMES:
        return "pdf"
    if mime in AUDIO_MIMES or mime.startswith('audio/'):
        return "audio"
    return "binary"
