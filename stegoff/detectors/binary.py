"""
Binary and structural steganography detection.

Covers: polyglot files, embedded files, format anomalies,
PDF steganography, audio LSB.
"""

from __future__ import annotations
import re
import struct
from stegoff.report import Finding, Severity, StegMethod


# Known file signatures (magic bytes)
FILE_SIGNATURES = {
    b'\x89PNG': 'PNG',
    b'\xff\xd8\xff': 'JPEG',
    b'GIF87a': 'GIF87a',
    b'GIF89a': 'GIF89a',
    b'PK\x03\x04': 'ZIP/DOCX/XLSX',
    b'PK\x05\x06': 'ZIP (empty)',
    b'Rar!\x1a\x07': 'RAR',
    b'\x7fELF': 'ELF executable',
    b'MZ': 'PE executable',
    b'%PDF': 'PDF',
    b'\x1f\x8b': 'GZIP',
    b'BM': 'BMP',
    b'RIFF': 'RIFF (WAV/AVI)',
    b'fLaC': 'FLAC',
    b'OggS': 'OGG',
    b'\xff\xfb': 'MP3',
    b'\xff\xf3': 'MP3',
    b'\xff\xf2': 'MP3',
    b'ID3': 'MP3 (ID3)',
    b'\x00\x00\x00\x1cftyp': 'MP4/MOV',
    b'\x00\x00\x00\x18ftyp': 'MP4/MOV',
    b'\x00\x00\x00\x20ftyp': 'MP4/MOV',
    b'SQLite format 3': 'SQLite',
    b'\xd0\xcf\x11\xe0': 'OLE (DOC/XLS/PPT)',
}


def detect_polyglot(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect polyglot files (valid as multiple file formats simultaneously).

    Polyglot files exploit the fact that some formats ignore data before
    or after their content. A file can be both a valid JPEG and a valid ZIP.
    """
    findings = []
    detected_formats = []

    # Check primary format (from start of file)
    primary = _identify_format(data[:20])

    # Scan for embedded file signatures throughout the file
    # Short signatures (2-3 bytes) can match randomly in binary data, so require
    # them to appear after the primary format's expected end or with corroboration.
    short_sigs = {sig for sig in FILE_SIGNATURES if len(sig) <= 3}
    for offset in range(1, min(len(data) - 4, 100000), 1):
        for sig, fmt in FILE_SIGNATURES.items():
            if data[offset:offset+len(sig)] == sig:
                # Found a file signature not at the start
                if fmt != primary:
                    # Skip short signatures (<=3 bytes) that match randomly
                    # inside binary formats like WAV/audio/images
                    if sig in short_sigs:
                        continue
                    detected_formats.append((offset, fmt, sig))

    # Also check from the end (appended files)
    # ZIP files can be detected from end-of-central-directory
    eocd_pos = data.rfind(b'PK\x05\x06')
    if eocd_pos > 0 and primary != 'ZIP/DOCX/XLSX':
        detected_formats.append((eocd_pos, 'ZIP (appended)', b'PK\x05\x06'))

    if detected_formats:
        # Deduplicate by format type
        unique_formats = {}
        for offset, fmt, sig in detected_formats:
            if fmt not in unique_formats or offset < unique_formats[fmt][0]:
                unique_formats[fmt] = (offset, sig)

        if len(unique_formats) > 0:
            format_list = [f"{fmt} at offset {off}" for fmt, (off, _) in unique_formats.items()]
            findings.append(Finding(
                method=StegMethod.POLYGLOT,
                severity=Severity.CRITICAL,
                confidence=0.90,
                description=f"Polyglot file: primary format {primary}, also contains {', '.join(f for f in unique_formats)}",
                evidence="; ".join(format_list[:10]),
                metadata={
                    "primary_format": primary,
                    "embedded_formats": list(unique_formats.keys()),
                },
            ))

    return findings


def detect_embedded_files(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Scan for file signatures embedded within the data (binwalk-style).

    More targeted than polyglot detection — looks for common payload
    formats that steganography tools embed.
    """
    findings = []

    # Check for ZIP/archive appended to image
    if data[:2] in (b'\xff\xd8', b'\x89P', b'BM', b'GI'):
        pk_pos = data.find(b'PK\x03\x04', 4)
        if pk_pos > 0:
            remaining = len(data) - pk_pos
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.CRITICAL,
                confidence=0.92,
                description=f"ZIP archive embedded at offset {pk_pos} ({remaining} bytes)",
                evidence=f"PK header at offset {pk_pos}",
                location=f"offset {pk_pos}",
                metadata={"offset": pk_pos, "embedded_format": "ZIP", "size": remaining},
            ))

        # Check for RAR
        rar_pos = data.find(b'Rar!\x1a\x07', 4)
        if rar_pos > 0:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.CRITICAL,
                confidence=0.92,
                description=f"RAR archive embedded at offset {rar_pos}",
                evidence=f"RAR header at offset {rar_pos}",
                location=f"offset {rar_pos}",
                metadata={"offset": rar_pos, "embedded_format": "RAR"},
            ))

    # Check for executable inside non-executable
    primary = _identify_format(data[:20])
    if primary and 'executable' not in primary.lower():
        if data.find(b'\x7fELF', 4) > 0:
            pos = data.find(b'\x7fELF', 4)
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.CRITICAL,
                confidence=0.95,
                description=f"ELF executable embedded inside {primary} at offset {pos}",
                evidence="ELF magic bytes found",
                location=f"offset {pos}",
                metadata={"offset": pos, "embedded_format": "ELF"},
            ))

        mz_pos = data.find(b'MZ', 4)
        if mz_pos > 0:
            # Verify it's likely a real PE (check for PE header)
            if mz_pos + 64 < len(data):
                try:
                    pe_offset = struct.unpack('<I', data[mz_pos+60:mz_pos+64])[0]
                    if mz_pos + pe_offset + 4 < len(data):
                        if data[mz_pos+pe_offset:mz_pos+pe_offset+4] == b'PE\x00\x00':
                            findings.append(Finding(
                                method=StegMethod.EMBEDDED_FILE,
                                severity=Severity.CRITICAL,
                                confidence=0.95,
                                description=f"Windows PE executable embedded inside {primary} at offset {mz_pos}",
                                evidence="MZ + PE signature confirmed",
                                location=f"offset {mz_pos}",
                                metadata={"offset": mz_pos, "embedded_format": "PE"},
                            ))
                except Exception:
                    pass

    return findings


def detect_pdf_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """
    Detect steganography in PDF files.

    PDFs can hide data in: unused objects, JavaScript, embedded streams,
    incremental updates, whitespace between objects, and metadata.
    """
    if not data.startswith(b'%PDF'):
        return []

    findings = []

    js_count = data.count(b'/JavaScript') + data.count(b'/JS ')

    # JavaScript in PDFs is suspicious (potential payload delivery)
    if js_count > 0:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.HIGH,
            confidence=0.75,
            description=f"PDF contains {js_count} JavaScript reference(s)",
            evidence="JavaScript can execute payloads or exfiltrate hidden data",
            metadata={"javascript_refs": js_count},
        ))

    # Large gap between %%EOF and actual end of file
    eof_pos = data.rfind(b'%%EOF')
    if eof_pos >= 0:
        trailing = len(data) - eof_pos - 5
        if trailing > 100:
            findings.append(Finding(
                method=StegMethod.TRAILING_DATA,
                severity=Severity.HIGH,
                confidence=0.85,
                description=f"{trailing} bytes after PDF %%EOF marker",
                evidence=f"trailing data preview: {data[eof_pos+5:eof_pos+55].hex()}",
                metadata={"trailing_bytes": trailing},
            ))

    # Check for incremental updates (can hide replaced content)
    eof_count = data.count(b'%%EOF')
    if eof_count >= 2:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.55,
            description=f"PDF has {eof_count} %%EOF markers (incremental updates may hide content)",
            evidence=f"{eof_count} revision layers detected",
            metadata={"eof_count": eof_count},
        ))

    # Check for form fields (AcroForm) which can hide data
    if b'/AcroForm' in data or b'/FT ' in data:
        form_count = data.count(b'/FT ')
        if form_count > 0:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.60,
                description=f"PDF contains {form_count} form field(s) that may hide data",
                evidence="AcroForm fields can contain invisible payloads",
                metadata={"form_fields": form_count},
            ))

    # Check for unusually large streams (could contain hidden data)
    stream_sizes = []
    for match in re.finditer(b'stream\r?\n', data):
        start = match.end()
        end = data.find(b'endstream', start)
        if end > start:
            stream_sizes.append(end - start)

    if stream_sizes:
        avg_size = sum(stream_sizes) / len(stream_sizes)
        max_size = max(stream_sizes)
        if max_size > avg_size * 10 and max_size > 50000:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.50,
                description=f"PDF stream outlier: {max_size} bytes (avg: {avg_size:.0f})",
                evidence="Unusually large stream may contain hidden data",
                metadata={"max_stream": max_size, "avg_stream": round(avg_size)},
            ))

    return findings


def detect_gzip_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect hidden data in GZip FEXTRA and FCOMMENT header fields."""
    if len(data) < 10 or data[:2] != b'\x1f\x8b':
        return []

    findings = []
    flg = data[3]
    pos = 10

    # FEXTRA: extra field that most legitimate gzip files don't use
    if flg & 0x04:
        if pos + 2 <= len(data):
            xlen = int.from_bytes(data[pos:pos+2], 'little')
            extra = data[pos+2:pos+2+xlen]
            pos += 2 + xlen
            if xlen > 8:
                findings.append(Finding(
                    method=StegMethod.EMBEDDED_FILE,
                    severity=Severity.HIGH,
                    confidence=0.80,
                    description=f"GZip FEXTRA field contains {xlen} bytes of hidden data",
                    evidence=f"Extra data: {extra[:100]}",
                    metadata={"field": "FEXTRA", "size": xlen},
                ))

    # FNAME: skip null-terminated original filename
    if flg & 0x08:
        end = data.find(b'\x00', pos)
        if end >= 0:
            pos = end + 1

    # FCOMMENT: null-terminated comment, rarely used legitimately
    if flg & 0x10:
        end = data.find(b'\x00', pos)
        if end >= 0:
            comment = data[pos:end]
            if len(comment) > 5:
                findings.append(Finding(
                    method=StegMethod.EMBEDDED_FILE,
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    description=f"GZip FCOMMENT field contains {len(comment)} bytes",
                    evidence=f"Comment: {comment[:100]}",
                    metadata={"field": "FCOMMENT", "size": len(comment)},
                ))

    return findings


def detect_tar_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect hidden data in TAR PAX extended headers and comments."""
    findings = []

    # TAR blocks are 512 bytes. Check for PAX headers (typeflag 'x' or 'g')
    pos = 0
    while pos + 512 <= len(data):
        block = data[pos:pos+512]
        # Check if it's a valid tar header (has a name and ustar magic)
        name = block[:100].rstrip(b'\x00').decode('ascii', errors='replace')
        typeflag = chr(block[156]) if block[156] != 0 else ''

        if not name and block == b'\x00' * 512:
            break  # End of archive

        # Parse size from octal
        try:
            size_str = block[124:136].rstrip(b'\x00').strip()
            if size_str:
                size = int(size_str, 8)
            else:
                size = 0
        except ValueError:
            size = 0

        if typeflag in ('x', 'g') and size > 0:
            # PAX extended header: contains key=value pairs
            pax_data = data[pos+512:pos+512+size]
            pax_text = pax_data.decode('utf-8', errors='replace')

            # Look for non-standard keys that could hide data
            standard_keys = {'path', 'linkpath', 'size', 'uid', 'gid', 'uname',
                           'gname', 'mtime', 'atime', 'ctime', 'charset', 'comment',
                           'hdrcharset', 'realtime.', 'security.'}
            for line in pax_text.split('\n'):
                if '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        key = parts[0].split(' ')[-1]  # format: "len key=value"
                        if not any(key.startswith(s) for s in standard_keys):
                            findings.append(Finding(
                                method=StegMethod.EMBEDDED_FILE,
                                severity=Severity.HIGH,
                                confidence=0.80,
                                description=f"TAR PAX header contains non-standard field: {key}",
                                evidence=f"{line[:200]}",
                                metadata={"field": key, "typeflag": typeflag},
                            ))
                            break  # One finding per PAX block is enough

            # Also flag if comment field has content
            if 'comment=' in pax_text:
                findings.append(Finding(
                    method=StegMethod.EMBEDDED_FILE,
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    description="TAR PAX header contains comment field with data",
                    evidence=pax_text[:200],
                    metadata={"field": "comment"},
                ))

        # Move to next block
        blocks = (size + 511) // 512
        pos += 512 + blocks * 512

        if pos > len(data):
            break

    return findings


def detect_pcap_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect steganography in PCAP packet captures."""
    # PCAP magic: d4 c3 b2 a1 (little-endian) or a1 b2 c3 d4 (big-endian)
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return []

    findings = []

    # Scan raw packet data for readable ASCII payloads (hidden messages in packets)
    ascii_runs = []
    current = []
    for b in data[24:]:  # skip PCAP global header
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= 15:
                ascii_runs.append(''.join(current))
            current = []
    if len(current) >= 15:
        ascii_runs.append(''.join(current))

    # Check for base32/base64 encoded data in payloads (DNS tunneling etc)
    for run in ascii_runs:
        if re.search(r'[A-Z2-7]{20,}', run):  # base32 pattern
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.80,
                description="PCAP contains base32-encoded data (possible DNS tunnel)",
                evidence=f"Found: {run[:100]}",
                metadata={"technique": "dns_tunnel"},
            ))
            break
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', run):  # base64
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.75,
                description="PCAP contains base64-encoded payload data",
                evidence=f"Found: {run[:100]}",
                metadata={"technique": "pcap_payload"},
            ))
            break

    # Check for covert channel indicators: many small packets or unusual field patterns
    # Count packets
    pos = 24
    packet_count = 0
    le = data[:4] == b'\xd4\xc3\xb2\xa1'
    fmt = '<I' if le else '>I'
    while pos + 16 <= len(data):
        try:
            incl_len = struct.unpack(fmt, data[pos+8:pos+12])[0]
            packet_count += 1
            pos += 16 + incl_len
        except struct.error:
            break

    # High packet count with small payloads = covert channel pattern
    if packet_count > 20:
        avg_size = (len(data) - 24) / max(packet_count, 1)
        if avg_size < 100:  # very small packets
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.65,
                description=f"PCAP has {packet_count} small packets (avg {avg_size:.0f}B), possible covert channel",
                evidence=f"{packet_count} packets, avg size {avg_size:.0f} bytes",
                metadata={"packet_count": packet_count, "avg_size": round(avg_size)},
            ))

    # Scan for steg keywords and known steg tool signatures in packet payloads
    steg_keywords = [b'steg', b'hidden', b'secret', b'payload', b'covert']
    for kw in steg_keywords:
        if kw in data.lower():
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.85,
                description=f"PCAP contains steganography keyword: {kw.decode()}",
                evidence=f"Keyword '{kw.decode()}' found in packet data",
                metadata={"keyword": kw.decode()},
            ))
            break

    # Check for non-ASCII UTF-8 in packet payloads (unusual for network traffic)
    # Steg tools often embed Unicode payloads in packet data
    utf8_multibyte = sum(1 for i in range(24, len(data)) if data[i] > 127)
    if utf8_multibyte > 20 and len(data) > 100:
        ratio = utf8_multibyte / (len(data) - 24)
        if ratio > 0.02:
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.MEDIUM,
                confidence=0.65,
                description=f"PCAP contains {utf8_multibyte} non-ASCII bytes ({ratio:.1%}), unusual for network traffic",
                evidence="Non-ASCII content in packet payloads suggests embedded data",
                metadata={"non_ascii_bytes": utf8_multibyte, "ratio": round(ratio, 4)},
            ))

    return findings


def detect_sqlite_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect hidden data in SQLite databases."""
    if not data.startswith(b'SQLite format 3'):
        return []

    findings = []
    # Check for steganography-related table names
    steg_tables = [b'_steg', b'steg_', b'hidden', b'payload', b'secret', b'covert']
    for pattern in steg_tables:
        if pattern in data.lower():
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.80,
                description=f"SQLite contains suspicious table/field name matching '{pattern.decode()}'",
                evidence="Pattern found in database structure",
                metadata={"pattern": pattern.decode()},
            ))
            break

    # Check for readable text hidden in the database binary
    ascii_runs = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= 20:
                run = ''.join(current)
                if any(kw in run.lower() for kw in ('steg', 'hidden', 'payload', 'secret')):
                    ascii_runs.append(run)
            current = []

    if ascii_runs:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.HIGH,
            confidence=0.80,
            description="SQLite contains suspicious text data",
            evidence=f"Found: {ascii_runs[0][:150]}",
            metadata={"text_runs": len(ascii_runs)},
        ))

    return findings


def detect_midi_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect hidden data in MIDI files (SysEx messages, text events)."""
    if not data.startswith(b'MThd'):
        return []

    findings = []
    # SysEx messages: F0 ... F7 (can carry arbitrary data)
    sysex_count = data.count(b'\xf0')
    if sysex_count > 0:
        # Extract SysEx content
        for i in range(len(data)):
            if data[i] == 0xF0:
                end = data.find(b'\xf7', i + 1)
                if end > i:
                    payload = data[i+1:end]
                    if len(payload) > 10:
                        findings.append(Finding(
                            method=StegMethod.EMBEDDED_FILE,
                            severity=Severity.HIGH,
                            confidence=0.80,
                            description=f"MIDI SysEx message contains {len(payload)} bytes of data",
                            evidence=f"SysEx payload at offset {i}",
                            metadata={"offset": i, "size": len(payload)},
                        ))
                        break

    # MIDI text events (FF 01-07) can hide text
    text_events = []
    for marker in [b'\xff\x01', b'\xff\x02', b'\xff\x03', b'\xff\x04', b'\xff\x05']:
        pos = data.find(marker)
        if pos >= 0 and pos + 3 < len(data):
            length = data[pos + 2]
            text = data[pos+3:pos+3+length]
            try:
                decoded = text.decode('utf-8', errors='replace')
                if len(decoded) > 5:
                    text_events.append(decoded)
            except Exception:
                pass

    if text_events:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.70,
            description=f"MIDI contains {len(text_events)} text event(s)",
            evidence=f"Text: {text_events[0][:150]}",
            metadata={"text_events": len(text_events)},
        ))

    return findings


def detect_rtf_steganography(data: bytes, filepath: str = "") -> list[Finding]:
    """Detect hidden text groups in RTF documents."""
    if not data.startswith(b'{\\rtf'):
        return []

    findings = []
    text = data.decode('latin-1', errors='replace')

    # RTF hidden text: \v (hidden text toggle)
    if '\\v ' in text or '\\v1' in text:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.HIGH,
            confidence=0.85,
            description="RTF contains hidden text groups (\\v toggle)",
            evidence="Hidden text markers found in RTF structure",
            metadata={"technique": "rtf_hidden_text"},
        ))

    # Check info fields for hidden data
    info_fields = re.findall(r'\{\\info\{(.+?)\}', text, re.DOTALL)
    for field in info_fields:
        if any(kw in field.lower() for kw in ('steg', 'hidden', 'payload', 'secret')):
            findings.append(Finding(
                method=StegMethod.EMBEDDED_FILE,
                severity=Severity.HIGH,
                confidence=0.80,
                description="RTF info field contains suspicious content",
                evidence=f"Info: {field[:150]}",
                metadata={"technique": "rtf_info"},
            ))
            break

    # Check for base64/hex in RTF bookmarks or comments
    b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    if b64_matches:
        findings.append(Finding(
            method=StegMethod.EMBEDDED_FILE,
            severity=Severity.MEDIUM,
            confidence=0.65,
            description=f"RTF contains {len(b64_matches)} base64-encoded string(s)",
            evidence=f"First match: {b64_matches[0][:100]}",
            metadata={"b64_count": len(b64_matches)},
        ))

    return findings


def scan_binary(data: bytes, filepath: str = "") -> list[Finding]:
    """Run all binary/structural detectors."""
    findings: list[Finding] = []
    findings.extend(detect_polyglot(data, filepath))
    findings.extend(detect_embedded_files(data, filepath))
    findings.extend(detect_pdf_steganography(data, filepath))
    findings.extend(detect_gzip_steganography(data, filepath))
    findings.extend(detect_tar_steganography(data, filepath))
    findings.extend(detect_pcap_steganography(data, filepath))
    findings.extend(detect_sqlite_steganography(data, filepath))
    findings.extend(detect_midi_steganography(data, filepath))
    findings.extend(detect_rtf_steganography(data, filepath))
    return findings


def _identify_format(header: bytes) -> str:
    """Identify file format from header bytes."""
    for sig, fmt in FILE_SIGNATURES.items():
        if header[:len(sig)] == sig:
            return fmt
    return "unknown"
