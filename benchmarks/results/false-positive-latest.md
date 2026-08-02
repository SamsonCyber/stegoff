# StegOFF false-positive suite

- Generated: `2026-08-02T19:12:10Z`
- Cases: **40**
- False positives: **1**
- Errors: **0**
- FP rate: **2.5000%**
- Pass: **False**
- Elapsed: 8.86s

## By category

| Category | Total | FP | Errors |
|---|---:|---:|---:|
| code_inline | 6 | 0 | 0 |
| common_patterns | 4 | 0 | 0 |
| edge | 7 | 0 | 0 |
| english_prose | 4 | 0 | 0 |
| file_scan | 6 | 0 | 0 |
| image | 1 | 0 | 0 |
| international | 8 | 1 | 0 |
| technical | 4 | 0 | 0 |

## Failures

- **international/Chinese**: clean=False findings=["anomalous_unicode_blocks: 16 characters from 'CJK Unified Ideographs' block in Latin-dominant text"] error=None
