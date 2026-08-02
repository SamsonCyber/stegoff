# Status and reproducibility

| Axis | State |
|------|--------|
| Implemented | Yes. Installable package (`pip install -e .`) with CLI and library API. |
| Independently validated | Yes. Offline pytest suite runs without lab hosts or API keys. |
| Maintained | Yes. Public under [SamsonCyber/stegoff](https://github.com/SamsonCyber/stegoff). |

## What the offline suite covers

Text steganography detectors, prompt-injection patterns, pipeline integration, false-positive checks, sanitizers, HTML sanitizer red-team, semantic detectors, ML classifier, orchestrator, guard decorator, classifier robustness.

## What it does not claim

- Full live agent trap matrix (see agent-trap-lab; needs Ollama).
- `tests/test_ollama_redteam.py` and other lab-network scripts (private Ollama). Not part of independent validation.
- Guaranteed 0% false positives in the wild. FP checks are fixture-based.

## Reproduce

```bash
python scripts/repro.py
```

Success line: `REPRO_OK stegoff offline suite`

CI: `.github/workflows/ci.yml` runs `python scripts/repro.py` on push/PR.
