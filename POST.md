# StegOFF: A Three-Layer Defense Against Steganographic Attacks on AI Systems

## The Problem

Every major LLM (ChatGPT, Claude, Gemini) processes text from untrusted sources: user messages, uploaded files, web content, API inputs. Steganography lets an attacker hide instructions inside that content using invisible Unicode characters, modified pixel values, or synonym choices that look natural to humans but carry encoded payloads.

A zero-width character payload like this looks like normal text to a human:

> "Please review the quarterly report."

But contains an invisible instruction between every word:

> "Please `U+200C U+200D U+200C U+200C` review `U+200D U+200C U+200D U+200D` the quarterly report."

Those invisible characters decode to: `ignore all previous instructions`.

The attack surface is wide. Text can carry payloads via 14 different Unicode tricks. Images can hide data in pixel LSBs that survive visual inspection. PDFs, JSON files, code comments, audio samples, even the ordering of list items can encode hidden instructions. Existing tools cover 1-3 of these methods. None cover all of them, and none chain detection with sanitization.

StegOFF is a Python library that detects and destroys steganographic payloads across all media types before they reach an AI system. Three detection layers, 35+ methods, 30+ file formats, zero false positives.

## Architecture

```
Input (text, file, or bytes)
  |
  v
+----------------------------------------------------------+
|  Layer 1: Character-Level Detection                       |
|  35 detector functions across 5 categories                |
|  14 text + 11 image + 3 audio + 7 binary/structural      |
|  FREE, deterministic, 11ms median                         |
|                                                           |
|  Catches: 100% of known encoding tools (st3gg corpus)     |
|  Misses: sub-threshold signals, semantic encoding          |
+---------------------------+------------------------------+
                            | if clean AND use_llm=True
                            v
+----------------------------------------------------------+
|  Layer 2: LLM Semantic Detection                          |
|  Claude Haiku analyzes for synonym patterns,               |
|  structural encoding, register shifts                      |
|  ~$0.0001/scan, ~1 second                                 |
|                                                           |
|  Catches: all 4 Layer 1 bypasses                           |
|  F1 = 1.00 on test set                                    |
+---------------------------+------------------------------+
                            | optional sanitization
                            v
+----------------------------------------------------------+
|  Layer 3: Paraphrase Canonicalization                     |
|  LLM rewrites text using default word choices              |
|  Payload dies because carrier is replaced                  |
|  Chunk-sampled for large documents (fixed cost)            |
|                                                           |
|  Destroys payloads even when detection is uncertain        |
+----------------------------------------------------------+
```

The design principle behind the layers: each one catches what the previous one can't, and costs proportionally more. Most malicious content gets caught by the free Layer 1. Sophisticated attacks that evade character-level analysis hit Layer 2. The most advanced attacks (synonym encoding, structural steganography) are neutralized by Layer 3's paraphrase sanitization, which destroys the carrier rather than trying to detect the signal.

## How Each Layer Works

### Layer 1: Character-Level Detection (35 methods)

Layer 1 is deterministic, runs in milliseconds, and requires zero external dependencies for text analysis. It operates on the raw bytes and Unicode codepoints of the input.

**Text detection (14 methods)** scans for characters that shouldn't be there. Zero-width characters (U+200B, U+200C, U+200D) are invisible but carry binary data. Unicode tag characters (U+E0000 range) are completely invisible in all rendering contexts. Homoglyph substitution replaces Latin 'a' with Cyrillic 'а' (U+0430), visually identical but a different codepoint. The detector maps 150+ confusable characters across Cyrillic, Greek, Armenian, Cherokee, Roman Numerals, and Modifier Letters.

Each detector does more than flag suspicious characters. It extracts the encoded payload, decodes it where possible, and passes decoded content through a prompt injection scanner with 17 pattern categories. A zero-width payload that decodes to "ignore all previous instructions" gets flagged both as steganography and as prompt injection.

The trailing whitespace detector catches Snow-style encoding where spaces and tabs at the end of each line carry bits. The emoji substitution detector handles both binary (2-type) and multi-type (3-32 types) encoding schemes. The homoglyph detector includes a script-dominance check that prevents false positives on text that's genuinely written in Cyrillic.

**Image detection (11 methods)** applies statistical analysis to pixel data. The chi-square test measures whether LSB pair frequencies match the expected distribution for natural images. RS (Regular-Singular) analysis divides the image into groups, applies flipping functions, and measures how the regular-to-singular ratio deviates from clean images. Sample Pairs analysis examines adjacent pixel pairs for trace statistics. Bit-plane correlation measures whether the LSB plane has the spatial structure expected of natural images (correlation > 0.55) or the randomness of embedded data (correlation near 0.50).

Structural detectors check for PNG ancillary chunks with suspicious content, trailing data after EOF markers (PNG IEND, JPEG FFD9, GIF 3B), and metadata fields containing base64 or hex-encoded data. The ICC profile scanner extracts readable ASCII text from binary profile data, closing a bypass where attackers hide payloads in a field most tools explicitly skip.

**Audio detection** parses WAV (little-endian), AIFF (big-endian), and AU (big-endian) containers, extracts PCM sample data, and applies LSB correlation analysis, chi-square testing, and segment-level entropy analysis.

**Binary and structural detection** covers PDF steganography (JavaScript references, incremental updates, form fields, stream size outliers, post-EOF data), polyglot files (valid as multiple formats simultaneously), embedded file signatures (ZIP/RAR/ELF/PE inside images), GZip header fields (FEXTRA, FCOMMENT), TAR PAX extended headers, JSON structure scanning (numeric byte arrays that decode to ASCII, float-scaled encoding, suspicious key names), and code comment scanning across 7 comment syntaxes with ROT13 decode and injection pattern matching.

The text file router handles UTF-8, UTF-16 with BOM, and UTF-16LE/BE heuristic detection, preventing a bypass where attackers encode steg payloads in a file encoding the scanner doesn't support.

### Layer 2: LLM Semantic Detection

Layer 2 activates when Layer 1 finds nothing. It sends the first 3000 characters to Claude Haiku with a structured prompt that asks specifically about synonym encoding patterns, register shifts, invisible characters, and numeric encoding.

The key insight: an attacker encoding bits in synonym choices ("big" vs "large", "fast" vs "quick") leaves no character-level artifact. Every character is a valid, common Unicode codepoint. Every word is a real English word. The signal is in the pattern of choices, which requires language understanding to detect.

Haiku analyzes the text and returns a structured JSON response with a suspicion flag, confidence score, identified technique, and explanation. The prompt is calibrated to not flag normal variation in technical writing, domain jargon, or repeated/templated content.

For large documents, Layer 2 runs on sampled chunks independently. The document is split at paragraph boundaries, 8-10 chunks are randomly sampled, and each is analyzed separately. This keeps cost fixed regardless of document length (~$0.003 for a 50-page document) while detecting localized steganography.

In testing, Haiku identified synonym-encoded paragraphs at positions 12 and 37 out of 50 unique paragraphs, with zero false positives on the clean paragraphs.

### Layer 3: Paraphrase Canonicalization

Layer 3 applies the same principle as image re-encoding (which destroys LSB payloads by re-rendering pixels) to natural language. The LLM rewrites the text using its own default word choices, replacing every attacker-selected synonym with the most common alternative.

Example:
```
Input:  "The large dog ran across the big park."
Output: "The big dog ran across the big park."
                                          ^
                        LLM's default: "big" not "large"
```

The attacker encoded a bit by choosing "large" over "big". The LLM normalized it back to "big". The bit is gone.

This works as both detection and sanitization. Normal text changes ~5% during paraphrase (the LLM has minor stylistic preferences). Synonym-encoded text changes ~20% (many unnatural choices get corrected). The gap is the detection signal. But regardless of whether the detection threshold triggers, the output text is guaranteed clean because every word choice is the LLM's default.

## Testing Methodology

### Adversarial Corpus

StegOFF was tested against [st3gg](https://github.com/elder-plinius/st3gg), an open-source steganography toolkit with 100+ encoding techniques. Testing used two approaches:

**Static fixtures**: 69 pre-encoded files from st3gg's example corpus, covering 41 unique encoding techniques across 32 file extensions. Each file contains a known payload encoded by st3gg's generator.

**Live generation**: 68 payloads generated at test time by importing st3gg's encoder API directly. This includes a parameter sweep across 6 channel presets (R, G, B, RGB, RG, RGBA), 4 bit depths (1-4 bits per channel), and 3 encoding strategies (sequential, interleaved, spread). The encoder and detector run head-to-head on the same data.

### Red Team

Two rounds of adversarial attack development, totaling 27 unique bypass attempts designed by analyzing stegOFF's source code to target specific weaknesses.

**Round 1 (17 attacks against Layer 1):**
- LSB matching (±1 instead of replacement, designed to defeat chi-square)
- ICC profile injection (architectural exclusion of icc_profile from scanning)
- Unmapped homoglyphs (Roman Numerals, Cherokee, Modifier Letters)
- JSON numeric arrays ([72, 101, 108] = "Hel")
- Float-scaled encoding (7.2 at 10x scale = 72)
- UTF-16 encoding bypass
- ROT13 obfuscation in code comments
- Sub-threshold attacks (2 zero-width chars, sparse trailing whitespace, single confusable space)
- Semantic synonym encoding

After patching, 13/17 blocked by Layer 1. The remaining 4 (sub-threshold and semantic) are caught by Layer 2.

**Round 2 (10 attacks against all layers including LLM):**
- Micro-payload (2 bits in 5000 chars of padding)
- Timestamp microsecond encoding
- UUID steganography
- Medical jargon synonym choices
- Absence encoding (missing optional fields)
- SHA256 hash covert channel
- Indentation depth encoding
- Post-LLM-window payload
- List permutation encoding
- Decimal precision encoding

5/10 caught by the LLM. The remaining 5 (UUIDs, hashes, absence, list order, domain jargon) encode data in fields that are inherently arbitrary. These represent the theoretical floor of steganography detection. StegOFF provides canonicalization sanitizers (UUID regeneration, list sorting) that destroy these payloads without detecting them.

### False Positive Validation

33 clean inputs across:
- 20 text strings in 6 languages (English, Japanese, Arabic, Russian, Korean, French)
- 9 clean code/config files (Python, JSON, HTML, XML, YAML, Shell, SQL, CSS, INI)
- Clean images (PNG, JPEG) and audio (WAV)

**0 false positives** across all 33 inputs.

## Results

```
Layer 1 (character-level, free, 11ms median):
  Detection:     53/53  stegg corpus payloads (100%)
  False positive: 0/33  clean inputs (0.0%)
  Red team:      13/17  attacks blocked (76%)

Layer 2 (LLM semantic, ~$0.0001/scan):
  Precision:     100%
  Recall:        100%
  F1:            1.00
  False positive: 0/5 clean inputs

Layer 3 (paraphrase canonicalization, ~$0.0003/scan):
  Detection accuracy: 100% (4/4)
  Large doc (50 paragraphs): steg detected, clean passed

Test suite: 229 unique payloads, 238 test functions, 226 core tests passing
Codebase: 5,768 lines source, 3,313 lines tests, 9,081 total
```

## Competitive Landscape

| Capability | StegOFF | PromptSonar | Promptfoo | image_security_scanner |
|---|---|---|---|---|
| Text steg methods | 14 | 3 | 1-3 | 0 |
| Image steg methods | 11 | 0 | 0 | 3 (OCR) |
| Audio steg | 3 formats | 0 | 0 | 0 |
| Binary/PDF | 7 | 0 | 0 | 0 |
| LLM semantic layer | Yes | No | No | No |
| Sanitization | text + image + audio + structured | No | No | No |
| Decode-to-injection pipeline | Yes | No | No | No |
| Zero-dep core | Yes | Tree-sitter | N/A | Tesseract |

No existing tool combines multi-modal steganography detection with prompt injection scanning and content sanitization. The closest competitor (PromptSonar) covers 3 of stegOFF's 14 text methods and operates only on source code, not runtime content.

## Usage

```bash
pip install stegoff            # text detection, zero deps
pip install stegoff[full]      # + image/audio (numpy, Pillow, scipy)
pip install stegoff[llm]       # + LLM semantic layer (anthropic SDK)
```

```python
from stegoff import scan_text, scan_file, steg_guard

# Scan text
report = scan_text("user input here")
report = scan_text("user input", use_llm=True)  # with LLM layer

# Scan files
report = scan_file("upload.png")

# Decorator: auto-strip steg from function inputs
@steg_guard
def process_user_message(text: str) -> str:
    return llm.generate(text)

# FastAPI middleware: scan all incoming requests
from stegoff.server.middleware import StegOffMiddleware
app.add_middleware(StegOffMiddleware)
```

## What I Learned

Building a security tool that's adversarially tested against real encoding software taught me more about Unicode, image statistics, and LLM capabilities than any course could.

The most valuable technical insight: detection and sanitization are complementary strategies, not alternatives. Detection tries to distinguish signal from noise, which gets harder as the signal gets weaker. Sanitization replaces the carrier entirely, destroying any signal regardless of its strength. Image re-encoding, UUID regeneration, and paraphrase canonicalization all work on this principle. The strongest defense uses detection first (it's cheaper), then sanitization for what detection can't catch.

The most valuable engineering insight: red teaming your own code is the fastest way to improve it. Every bypass I designed against stegOFF's detectors led to a concrete fix. The 5 attacks that remain after both red team rounds represent the theoretical limits of generic steganography detection, which I can explain precisely rather than hand-waving.

---

*StegOFF is MIT-licensed. [Source on GitHub.](https://github.com/solosec/stegoff)*
