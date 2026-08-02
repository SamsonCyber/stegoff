# StegOFF redteam wave-2 probe

- Generated: `2026-08-02T19:43:19Z`
- Attack cases: **24**
- Bypasses: **4**
- Caught: **20**
- Bypass rate: **16.7%**
- Control FPs: **1**
- Elapsed: 11.913s

## By family

| Family | Total | Bypass | Caught | Error |
|---|---:|---:|---:|---:|
| agent_text | 11 | 4 | 7 | 0 |
| image_lsb | 4 | 0 | 4 | 0 |
| image_meta | 1 | 0 | 1 | 0 |
| image_struct | 4 | 0 | 4 | 0 |
| json_channel | 4 | 0 | 4 | 0 |

## Bypass list

- **agent_text/indent_bits**: clean=True n=0 methods=[] note=indent_bits
- **agent_text/quoted_printable**: clean=True n=0 methods=[] note=quoted_printable
- **agent_text/socratic_leak**: clean=True n=0 methods=[] note=socratic_leak
- **agent_text/policy_diff**: clean=True n=0 methods=[] note=policy_diff

## Notes

Image + structural + novel agent channels. Does not prove model obedience; only that `scan` / `scan_text` returned clean (or failed the targeted check).
