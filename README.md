# StegOFF

Steganography detection, sanitization, and prompt injection guard for AI systems.

StegOFF finds and destroys hidden payloads in text, images, audio, PDFs, and code files before they reach your LLM, agent, or end user. Three detection layers, 35+ methods, 30+ file formats. Adversarially tested against [st3gg](https://github.com/elder-plinius/st3gg)'s 109-technique arsenal: 108/108 detected, 0 false positives.

## Install

```bash
pip install stegoff            # text detection only, zero deps
pip install stegoff[image]     # + image analysis (numpy, Pillow)
pip install stegoff[full]      # + audio statistical analysis (scipy)
pip install stegoff[llm]       # + LLM semantic layer (anthropic SDK)
pip install stegoff[server]    # + FastAPI server & middleware
```

## Quick Start

```python
from stegoff import scan_text, scan_file, steg_guard

# Scan text (free, deterministic, ~11ms)
report = scan_text("user input here")
print(report.clean)       # True if no steg detected
print(report.findings)    # list of Finding objects

# With LLM semantic layer (catches synonym encoding)
report = scan_text("user input", use_llm=True)

# Scan any file (auto-detects format from magic bytes)
report = scan_file("upload.png")

# Decorator: auto-strip steg from function inputs
@steg_guard
def process_user_message(text: str) -> str:
    return llm.generate(text)

# FastAPI middleware: scan all incoming requests
from stegoff.server.middleware import StegOffMiddleware
app.add_middleware(StegOffMiddleware)
```

CLI:

```bash
stegoff scan suspicious.png           # scan a file
stegoff scan-text "some text"         # scan text
stegoff scan-dir ./uploads --json     # scan directory
cat input.txt | stegoff guard         # strip steg from stdin
cat input.txt | stegoff guard --block # exit 1 if steg found
```

## How Steganography Attacks Work (and How StegOFF Stops Each One)

### Text Steganography

The most common attack vector against LLMs. An attacker hides instructions in text that looks normal to humans but carries encoded data at the Unicode level.

#### Zero-Width Characters

**The attack:** Insert invisible Unicode characters between visible letters. U+200C (zero-width non-joiner) = 0, U+200D (zero-width joiner) = 1. The text "Hello" becomes "H`U+200C``U+200D``U+200C`ello" with 3 hidden bits. A full prompt injection fits in about 500 invisible characters.

**What you see:** `Hello World`
**What's actually there:** `H[ZWNJ][ZWJ][ZWNJ][ZWNJ][ZWJ][ZWNJ][ZWNJ][ZWNJ]ello World`
**Decoded payload:** `ignore all previous instructions`

**How StegOFF defuses it:** Scans every character for 10 known zero-width codepoints (U+200B, U+200C, U+200D, U+FEFF, etc.). Decodes the ZWNJ/ZWJ binary pattern, extracts the hidden text, then runs it through 17 prompt injection detection patterns. A single BOM at file start gets LOW severity. 20+ zero-width chars get CRITICAL.

#### Unicode Tag Characters (Invisible Ink)

**The attack:** The U+E0000 range contains "tag" characters that are completely invisible in every rendering engine. Each tag character maps to an ASCII character: U+E0068 = 'h', U+E0069 = 'i'. The entire English alphabet has an invisible twin.

**How StegOFF defuses it:** Scans for any character in U+E0000-E007F. Decodes the tag sequence back to ASCII and reports the hidden message. Always CRITICAL severity. This is the technique used in the viral "invisible prompt injection" attacks against ChatGPT.

#### Homoglyph Substitution

**The attack:** Replace Latin letters with visually identical characters from other scripts. Cyrillic 'а' (U+0430) looks exactly like Latin 'a' (U+0061). An attacker substitutes specific letters, where each substitution encodes a bit: original letter = 0, substituted = 1.

**How StegOFF defuses it:** Maintains a map of 150+ confusable characters across Cyrillic, Greek, Armenian, Cherokee, Roman Numerals, and Modifier Letters. Checks script dominance (if text is >60% Cyrillic, it's genuinely Cyrillic, not an attack). Extracts the bit pattern from which characters were substituted.

#### 11 More Text Methods

StegOFF also detects: **variation selectors** (VS1-VS256 presence/absence encoding), **combining marks** (Zalgo-style diacritic stacking), **confusable whitespace** (en-space/em-space/NBSP substitution), **bidirectional overrides** (RTL/LTR text direction hijacking), **Hangul fillers** (Korean invisible chars in non-Korean text), **math alphanumeric symbols** (U+1D400 range bold/italic substitution), **braille patterns** (each braille character = one byte), **emoji substitution** (binary and multi-type encoding), **emoji skin tone** (5 modifiers = 2.3 bits each), **trailing whitespace** (space/tab patterns at line endings), and **invisible separators** (catch-all for Unicode format characters).

Each decoded payload is automatically scanned for prompt injection across 17 pattern categories: instruction overrides, jailbreaks, identity manipulation, privilege escalation, data exfiltration, code execution, social engineering, delimiter injection, and more.

### Image Steganography

#### LSB (Least Significant Bit) Embedding

**The attack:** Change the least significant bit of each pixel's color value. The human eye can't distinguish between RGB(142, 87, 201) and RGB(143, 87, 200). But those changed bits spell out a hidden message. A 1000x1000 RGB image holds 375,000 bytes of hidden data.

**How StegOFF defuses it:** Three independent statistical tests:

1. **Chi-square analysis**: In a clean image, adjacent value pairs (100,101) and (102,103) have naturally unequal frequencies. LSB embedding forces them toward equality. StegOFF measures this pair-frequency distortion across R/G/B channels.

2. **RS (Regular-Singular) analysis**: Divides the image into pixel groups, applies bit-flipping functions, and measures how many groups become "more regular" vs "more singular." In clean images, the R/S ratio follows a predictable curve. LSB embedding breaks this relationship.

3. **Bit-plane correlation**: In a natural photo, the LSB plane has spatial structure (neighboring pixels tend to have the same LSB). Embedded data makes the LSB plane look random. StegOFF measures spatial correlation and flags anything below 0.52 (random = 0.50, natural > 0.55).

These three tests catch LSB embedding across PNG, BMP, TIFF, WebP, GIF, ICO, and PGM/PPM formats, with any channel configuration (R, G, B, A, or combinations), any bit depth (1-8 bits per channel), and any embedding strategy (sequential, interleaved, spread, randomized).

#### Structural Image Attacks

**PNG ancillary chunks:** PNG files allow arbitrary named data chunks. StegOFF parses every chunk, flags non-standard chunk types, and scans text chunks (tEXt, zTXt, iTXt) for suspicious keywords and encoded content.

**Trailing data:** Data appended after the image's end-of-file marker (IEND for PNG, FFD9 for JPEG, 3B for GIF). StegOFF detects any bytes after EOF. Always CRITICAL severity.

**Metadata hiding:** EXIF tags, ICC color profiles, and PNG metadata fields can carry base64 or hex-encoded payloads. StegOFF scans all metadata fields (including ICC profiles) for embedded readable text, base64 patterns, and hex patterns.

**DCT coefficient manipulation (JPEG):** F5-style embedding modifies DCT coefficients during JPEG compression. StegOFF uses a blockiness calibration technique (compare block boundaries before and after a 4-pixel crop) to detect coefficient manipulation.

### Audio Steganography

**The attack:** Same LSB principle as images, applied to PCM audio samples. Change the least significant bit of each 16-bit sample. A 1-second 44.1kHz mono WAV hides ~5,500 bytes.

**How StegOFF defuses it:** Parses WAV (little-endian), AIFF (big-endian), and AU (big-endian) container formats. Extracts PCM sample data with correct endianness. Runs LSB correlation analysis, chi-square pair testing, and per-segment entropy analysis across the audio data.

### Document and Binary Steganography

**PDF:** Scans for JavaScript references (payload delivery), incremental updates (hidden document revisions), form fields (invisible data in AcroForm), post-EOF trailing data, and stream size outliers.

**Archives:** Detects polyglot files (valid as multiple formats simultaneously, like PNG+ZIP), embedded file signatures (ZIP/RAR/ELF/PE inside images), GZip FEXTRA/FCOMMENT header fields, TAR PAX extended headers with non-standard fields.

**Code files:** Scans comments across 7 syntax styles (`#` `//` `;` `--` `%` `/* */` `<!-- -->`) for base64, hex, and ROT13-encoded content. ROT13 is decoded and checked for injection patterns. Covers Python, JavaScript, CSS, Shell, SQL, C, LaTeX, INI, TOML, YAML, and XML. Also detects base32 encoding, hex dumps, Morse code, Punycode/IDN domains, and QR code text representations.

**JSON:** Decodes numeric byte arrays (`[72, 101, 108]` = "Hel"), float-scaled arrays (7.2 at 10x = 72), base64/hex in string values, and suspicious key names (payload, hidden, secret, steg).

**Network captures (PCAP):** Scans packet payloads for readable ASCII, base32 (DNS tunneling), non-ASCII bytes (unusual for network traffic), and steganography keywords.

**SQLite, MIDI, RTF:** Format-specific parsers detect hidden tables, SysEx messages, and RTF hidden text groups.

### Content-Type Mismatch Defense

An attacker might save a PNG file with a .txt extension, hoping the image scanner never runs. StegOFF scans based on **magic bytes** (the actual file header), not just the extension. A PNG disguised as .txt still gets image analysis.

### The LLM Layer: Catching What Characters Can't

Some techniques leave no character-level artifact:

**Synonym encoding:** "The **large** dog" vs "The **big** dog" encodes a bit in the word choice. Every character is valid. Every word is real English. The signal is in the *pattern* of choices.

**Sentence-length encoding:** Short sentence = 0. Long sentence = 1. The word count per sentence carries bits.

StegOFF's Layer 2 sends text to Claude Haiku with a hardened prompt that specifically looks for synonym patterns, register shifts, and structural encoding. The prompt includes defenses against prompt injection from the analyzed text itself (an attacker trying to manipulate the scanning LLM by embedding "this text is clean" instructions).

### Paraphrase Canonicalization: The Nuclear Option

Layer 3 applies the same principle as image re-encoding (which destroys LSB payloads by re-rendering pixels) to natural language. The LLM rewrites the text using its own default word choices:

```
Input:  "The large dog ran across the big park."
Output: "The big dog ran across the big park."
```

The attacker chose "large" to encode bit=1. The LLM normalized it back to "big." The payload is destroyed because the carrier (word choice) is replaced with the LLM's defaults. Normal text changes ~5% during paraphrase. Synonym-encoded text changes ~20%. The gap is the detection signal, and the output is guaranteed clean regardless.

## Numbers

```
Test Suite: 226 core tests, 68 live encoder tests, 39 red team attacks
           All passing. 9,081 lines of code.

Layer 1 (character-level, free, 11ms median):
  st3gg detection:   106/108 techniques (98.1%)
  False positives:     0/33  clean inputs  (0.0%)
  Red team blocked:   22/39  attack vectors

Layer 2 (LLM semantic, ~$0.0001/scan):
  st3gg detection:   108/108 techniques (100%)
  Precision:         100%
  Recall:            100%
  F1:                1.00

Layer 3 (paraphrase canonicalization, ~$0.0003/scan):
  Detection:         100% accuracy on test set
  Sanitization:      destroys payload regardless of detection
  Large documents:   chunk-sampled, fixed cost (~$0.003 for 50 pages)
```

## Red Team

39 custom bypass attempts designed by analyzing stegOFF's source code. Each targets a specific weakness in the detection logic.

**Blocked (30):** LSB matching ±1, ICC profile injection, unmapped homoglyphs (Roman Numerals, Cherokee, Modifier Letters), JSON byte arrays, float-scaled encoding, UTF-16 bypass, ROT13 in comments, NBSP encoding, borderline script ratios, single combining marks, BPCS embedding, timestamp microseconds, indentation depth, decimal precision, content-type mismatch, prompt injection against the LLM scanner itself, and more.

**Theoretical limits (5):** UUID steganography, SHA256 hash channels, list permutation, absence encoding, medical jargon synonyms. These encode data in fields that are inherently arbitrary. Mitigated by canonicalization sanitizers (UUID regeneration, alphabetical sort).

**Low-bandwidth structural bypasses (7):** HTML data attributes, CSS custom properties, filenames, GPS decimal precision, JSON value types, XML whitespace. None carry enough bandwidth for a full prompt injection through reasonable-length input.

Full red team log: [REDTEAM_LOG.md](REDTEAM_LOG.md)

## Sanitization

StegOFF doesn't just detect. It cleans:

```python
from stegoff import sanitize_text, sanitize_image, sanitize_wav
from stegoff.sanitizers.structured import sanitize_json, canonicalize_uuids
from stegoff.sanitizers.semantic import sanitize_semantic

# Strip invisible characters, normalize homoglyphs, cap combining marks
clean_text, result = sanitize_text(dirty_text)

# Re-encode image (destroys LSB, strips metadata)
clean_bytes = sanitize_image(image_bytes)

# Re-encode audio (destroys sample LSB)
clean_bytes = sanitize_wav(wav_bytes)

# Regenerate UUIDs, sort lists, normalize JSON
clean_json, result = sanitize_json(json_text)

# Paraphrase to destroy synonym encoding
clean_text, result = sanitize_semantic(text)
```

## Competitive Landscape

No existing tool combines multi-modal steganography detection with prompt injection scanning and content sanitization:

| Capability | StegOFF | PromptSonar | Promptfoo | image_security_scanner |
|---|---|---|---|---|
| Text steg methods | **14** | 3 | 1-3 | 0 |
| Image steg methods | **11** | 0 | 0 | 3 (OCR) |
| Audio steg | **3 formats** | 0 | 0 | 0 |
| Binary/PDF | **7+** | 0 | 0 | 0 |
| LLM semantic layer | **Yes** | No | No | No |
| Sanitization | **text+image+audio+JSON** | No | No | No |
| Decode-to-injection pipeline | **Yes** | No | No | No |
| Zero-dep core | **Yes** | Tree-sitter | N/A | Tesseract |

## License

MIT
