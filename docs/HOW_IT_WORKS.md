# How StegOFF works (in depth)

This doc is for people who need more than `check` / `clean`. It describes the real code path in this repo, what each layer is for, and what it does **not** do.

Runnable companion: `python examples/demo_how_it_works.py`.

---

## 1. Problem StegOFF is built for

LLM agents treat text (and sometimes files) as instructions or trusted data. Attackers hide instructions in:

1. **Invisible Unicode** (zero-width, tags, bidi) so a human sees one string and the model sees another.
2. **Lookalike characters** (homoglyphs) so keyword filters miss "password" or "admin".
3. **Plain language jailbreaks** ("ignore previous instructions…") with no stego at all.
4. **Encoded wrappers** (base64, multi-layer) that decode into injection text.
5. **Semantic framing** (fake journals, one-sided marketing) that bias agents without classic jailbreak keywords.
6. **HTML hiding** (`display:none`, comments, oversized aria-labels) for browsing agents.

StegOFF is a **pre-ingestion gate**: scan before the model runs, optionally strip stego channels, then decide whether to forward the string.

It is not a full agent runtime, not an LLM firewall product, and not a guarantee that the model will obey your system prompt.

---

## 2. Two verbs, two different jobs

| Verb | Job | Changes the text? |
|------|-----|-------------------|
| **check** (`scan` / CLI `stegoff x`) | Detect and report | No |
| **clean** (`sanitize_text` / CLI `stegoff clean`) | Strip known stego characters | Yes (best-effort) |

Important split:

- **Stego channels** (zero-width, bidi, many homoglyphs): clean can remove or normalize them.
- **English intent** (jailbreak prose): clean leaves the words. The **finding** is the signal to **block** or **refuse to send**, not to rewrite the sentence into something "safe."

If you only call `clean` and then always send the result to the model, you will still ship plain-language injection. Correct use:

```text
report = check(user_text)
if not report.clean and report.prompt_injection_detected:
    refuse or quarantine
else:
    model_input = clean(user_text)   # strip stego, then send
```

---

## 3. End-to-end data flow

```text
                    +------------------+
  path / text / bytes -->|  scan / check   |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
              v              v              v
           text path     image/pdf      audio/binary
              |           (optional)     (optional)
              v
     orchestrator.scan_text
              |
    +---------+----------+----------+----------+----------+
    |         |          |          |          |          |
    v         v          v          v          v          v
  HTML     multi-     Unicode    raw        authority  semantic
  entity   decode     stego      injection  / polar.   ML
  decode   base64     detectors  patterns   heuristics classifier
    |         |          |          |          |          |
    +---------+----------+----------+----------+----------+
                             |
                             v
                      ScanReport
                   clean, findings[],
                   highest_severity,
                   prompt_injection_detected,
                   semantic_manipulation_detected
                             |
            +----------------+----------------+
            |                                 |
            v                                 v
     human/CLI summary                  clean() path
     (no mutation)                 sanitizers.text.sanitize_text
                                          |
                                          v
                                   stripped string
```

Entry points:

| API | Module | Role |
|-----|--------|------|
| `check` / `scan` | `__init__.py` → `orchestrator.scan` | Type-detect path vs text vs bytes |
| `scan_text` | `orchestrator.scan_text` | Full text pipeline below |
| `scan_file` | `orchestrator.scan_file` | MIME/route to image, audio, binary, or text |
| `clean` | `sanitize_text` | Strip stego sets; return string |
| `@steg_guard` | `guard.py` | Decorate callables; strip or raise |
| CLI | `cli.py` | Default `stegoff <target>` → scan |

---

## 4. Text pipeline (`scan_text`) step by step

Source of truth: `stegoff/orchestrator.py` → `scan_text`.

### 4.1 HTML entity pass

- Unescape entities (`html.unescape`).
- If many **numeric** entities appear (`&#...;`), add an `HTML_ENTITY` finding (encoding channel).
- Re-run Unicode stego detectors on the unescaped string so stego hidden behind entities is not missed.

### 4.2 Multi-layer encoding (base64-looking blobs)

- Regex finds long base64-like candidates.
- Decode (and simple multi-decode variants).
- Run **injection** patterns on decoded bytes.
- Only raise `MULTI_ENCODING` when decoded content looks like injection (cuts noise on JWTs and random blobs).

### 4.3 Unicode steganography (`detectors/text.py`)

`scan_text_all` runs a fixed set of character-class detectors. Typical methods:

| Method enum | What it looks for |
|-------------|-------------------|
| `ZERO_WIDTH` | ZWSP, ZWNJ, ZWJ, BOM, word joiner, … |
| `UNICODE_TAGS` | Tag block U+E0000 (invisible ink) |
| `VARIATION_SELECTORS` | VS1–VS256 channels |
| `HOMOGLYPHS` | Cyrillic/Greek/fullwidth lookalikes mapped to Latin |
| `BIDI_OVERRIDES` | RTL/LTR overrides that reorder display |
| `CONFUSABLE_WHITESPACE` | EN/EM/thin spaces as side channel |
| `COMBINING_MARKS` | Stacked diacritics |
| `HANGUL_FILLER` | Fillers outside Korean context |
| Math / braille / emoji variants | Optional / lower priority channels |

Each hit becomes a `Finding` with severity, confidence, optional `decoded_payload`, and evidence.

If a stego finding carries a **decoded payload**, that payload is also run through injection detection (stego → plaintext jailbreak).

### 4.4 Structural text

- JSON-looking documents: structure scan for odd embedded strings.
- Comment / encoded-content helpers for code-like blobs.

### 4.5 Raw prompt-injection pass (`detectors/prompt_injection.py`)

Runs on the **raw** string (not only on decoded stego). Patterns cover, among others:

- instruction override ("ignore … previous … instructions")
- identity / persona hijack ("you are …", "act as …")
- system-prompt probes and reveal verbs
- jailbreak keywords (DAN, developer mode, …)
- exfil / URL / tool-call shaped lines
- delimiter injection (`</system>`, `[INST]`, …)

Also applies light **leetspeak normalization** so `1gn0re` style variants still match.

This layer is **regex heuristics**. It is fast and explainable. It is not a semantic understanding of every paraphrase.

### 4.6 Optional L2 LLM / transformer (`use_llm=True`)

Only if the caller sets `use_llm=True` **and** the report is still clean after cheaper layers:

1. Prefer a local transformer detector if installed.
2. Else Anthropic Haiku-style path via `detect_semantic_steg` (needs API key).

Default `check()` / CLI does **not** require this path.

### 4.7 Semantic manipulation (agent defense)

Always on for text scans:

| Detector | Module | Role |
|----------|--------|------|
| Authority fabrication | `authority.py` | Fake journals, bogus institutions, suspicious NIST/PEP-shaped claims |
| Polarization bias | `polarization.py` | Superlative saturation, one-sided framing |
| ML semantic classifier | `semantic_classifier.py` | TF-IDF + logistic regression over classes including authority / polarization / RAG / few-shot style attacks (shipped pickle under `detectors/models/`) |

These target **visible, well-written** manipulation that has no zero-width characters. Findings set `semantic_manipulation_detected` on the report.

---

## 5. File pipeline (`scan_file`)

1. Size guard (oversized files rejected with a critical finding).
2. MIME guess from extension and magic bytes.
3. Route:

```text
image/*  -> detectors/image.py   (needs stegoff[image])
audio/*  -> detectors/audio.py   (needs stegoff[full])
pdf/bin  -> detectors/binary.py
text/*   -> decode bytes as text, then scan_text
```

4. Filename itself may be scanned for encoded injection (long base64-like stems).

If optional deps are missing, image/audio paths degrade (import guards / empty findings) rather than always crashing the text path.

---

## 6. Cleaning (`clean` / `sanitize_text`)

Source: `stegoff/sanitizers/text.py`.

Walks each character and, by default:

| Action | Default |
|--------|---------|
| Strip zero-width | on |
| Strip Unicode tags | on |
| Strip variation selectors | on |
| Strip bidi overrides | on |
| Strip Hangul fillers (non-Korean context) | on |
| Replace homoglyphs with Latin | on |
| Replace confusable whitespace with ASCII space | on |
| Cap combining marks per base | on |
| Strip math alphanumeric / braille / skin tones | **off** (ambiguous; enable if you need them) |

Returns `(cleaned_text, TextSanitizeResult)` with counts of removed/replaced chars. `clean()` in the public API returns only the string.

HTML cleaning is separate: `sanitize_html` / `scan_html` (BeautifulSoup if installed). Hidden CSS, comments, oversized aria-labels, suspicious meta, ld+json scripts.

---

## 7. Guard paths (runtime integration)

### Decorator `@steg_guard`

`stegoff/guard.py`:

- Scans string arguments (all, or named kwargs).
- `on_detect="strip"` (default): replace arg with `sanitize_text` output.
- `on_detect="raise"`: raise `StegDetected` / `PromptInjectionDetected`.
- `on_detect="log"`: warn, pass original.
- `block_injection=True`: injection findings can force raise even in strip mode (see implementation).

### CLI `guard`

Reads stdin. If dirty and `--block`, exit 2. Else print stripped text on stdout; findings summary on stderr.

### FastAPI middleware

`stegoff.server.middleware.StegOffMiddleware` scans request bodies for server deployments (`stegoff[server]`).

---

## 8. Report object

`ScanReport` (`report.py`):

| Field | Meaning |
|-------|---------|
| `clean` | No findings |
| `findings` | List of `Finding` |
| `highest_severity` | Max severity enum |
| `prompt_injection_detected` | Any injection-method finding |
| `semantic_manipulation_detected` | Authority / polarization / hidden HTML class findings |
| `summary()` | Multi-line human text for CLI |
| `brief()` | One-line status |
| `to_json()` | Machine output |

`Finding` carries method, severity, confidence (0–1), description, evidence, optional decoded payload, location, metadata.

---

## 9. Severity and exit codes

CLI / automation convention:

| Code | Meaning |
|------|---------|
| 0 | Clean |
| 2 | Findings present |
| 1 | Usage / hard error |

Severity order: CLEAN < LOW < MEDIUM < HIGH < CRITICAL.

Stego alone is often LOW/MEDIUM. Injection multi-hits escalate to CRITICAL. Semantic ML can land HIGH without any stego.

---

## 10. What StegOFF does not do

1. **Does not** rewrite jailbreak English into safe English.
2. **Does not** replace model-level refusal training or tool allowlists.
3. **Does not** claim zero false positives on all natural language.
4. **Does not** fully cover every stego scheme ever published (new encodings appear; detectors are a known catalog).
5. **Does not** run L2 LLM analysis unless you opt in with `use_llm=True` and credentials/models.

Defense in depth still needs: least-privilege tools, output filtering, human approval for high-risk actions, and scope gates on agent fire paths.

---

## 11. Map of modules (code tour)

```text
stegoff/
  __init__.py          check, clean, re-exports
  cli.py               default scan, clean, guard
  orchestrator.py      scan_text / scan_file / scan routing
  report.py            Finding, ScanReport, Severity, StegMethod
  guard.py             @steg_guard
  detectors/
    text.py            Unicode stego set
    prompt_injection.py  regex injection bank
    authority.py       fake authority heuristics
    polarization.py    framing / superlative density
    semantic_classifier.py  shipped TF-IDF+LR model
    image.py audio.py binary.py  optional file types
    trapsweep.py       HTML trap helpers
  sanitizers/
    text.py            clean()
    html.py            sanitize_html / scan_html
    image.py audio.py  optional
  server/              FastAPI app + middleware
  traps/               trap battery (advanced / eval)
```

---

## 12. Recommended usage patterns

**Chat / agent input**

```python
from stegoff import check, clean

def admit(user_text: str) -> str:
    r = check(user_text)
    if r.prompt_injection_detected or r.highest_severity.name == "CRITICAL":
        raise ValueError(r.summary())
    return clean(user_text)
```

**Decorator**

```python
from stegoff import steg_guard

@steg_guard(on_detect="strip", block_injection=True)
def handle(msg: str) -> str:
    return llm(msg)
```

**Batch files**

```bash
stegoff scan-dir ./uploads -e .txt .md --json
```

**Learn by running**

```bash
python examples/demo_how_it_works.py
```

---

## 13. Further reading in this repo

| Doc / path | Contents |
|------------|----------|
| [examples/README.md](../examples/README.md) | Short flow + sample list |
| [examples/demo_how_it_works.py](../examples/demo_how_it_works.py) | Live obfuscation → detect → clean |
| [STATUS.md](../STATUS.md) | What is independently validated offline |
| `stegoff/orchestrator.py` | Authoritative text/file pipeline |
| `stegoff/detectors/prompt_injection.py` | Pattern catalog |
| `stegoff/sanitizers/text.py` | Clean semantics and toggles |
