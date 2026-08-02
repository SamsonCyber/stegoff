"""
False-positive suite for StegOFF.

Runs legitimate (should-be-clean) samples through scan_text / scan and reports
false positives. Writes JSON + markdown under benchmarks/results/.

Usage:
    python benchmarks/false_positive_suite.py
    python benchmarks/false_positive_suite.py --json-only
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stegoff.orchestrator import scan, scan_file, scan_text  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"


@dataclass
class CaseResult:
    category: str
    name: str
    clean: bool
    findings: list[str] = field(default_factory=list)
    error: str | None = None


def _findings(report) -> list[str]:
    out = []
    for f in getattr(report, "findings", []) or []:
        method = getattr(getattr(f, "method", None), "value", None) or str(getattr(f, "method", "?"))
        desc = getattr(f, "description", "") or ""
        out.append(f"{method}: {desc}".strip())
    return out


def cases_text() -> list[tuple[str, str, str]]:
    """(category, name, text)"""
    items: list[tuple[str, str, str]] = []

    english = [
        "The quick brown fox jumps over the lazy dog.",
        "Meeting at 3pm in Conference Room B. Bring the Q3 report.",
        "Dear Customer,\n\nThank you for your purchase.\nOrder #12345 ships tomorrow.\n\nBest regards,\nSupport Team",
        "Recipe: Preheat oven to 375F. Mix 2 cups flour, 1 cup sugar, 3 eggs. Bake 25 minutes until golden brown.",
    ]
    for i, t in enumerate(english):
        items.append(("english_prose", f"en_{i}", t))

    intl = [
        ("Japanese", "日本語のテスト文章です。東京は美しい都市です。"),
        ("Chinese", "这是一个测试文档。北京是中国的首都。"),
        ("Arabic", "مرحبا بالعالم. هذا نص عربي عادي."),
        ("Russian", "Привет мир. Это обычный русский текст."),
        ("Korean", "한국어 텍스트입니다. 서울은 아름다운 도시입니다."),
        ("French", "Le café résumé était très intéressant."),
        ("German", "Die Konferenz findet am Freitag statt."),
        ("Spanish", "El informe trimestral muestra un crecimiento significativo."),
    ]
    for label, t in intl:
        items.append(("international", label, t))

    technical = [
        "SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 LIMIT 50;",
        "git commit -m 'fix: resolve null pointer in auth middleware'",
        "docker run -d --name postgres -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:16",
        "pip install numpy>=1.24 pandas scikit-learn",
    ]
    for i, t in enumerate(technical):
        items.append(("technical", f"tech_{i}", t))

    patterns = [
        "Check https://docs.python.org/3/library/pathlib.html for details",
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "UUID: 550e8400-e29b-41d4-a716-446655440000",
        "MAC: 00:1A:2B:3C:4D:5E | IP: 192.168.1.100 | Port: 8443",
    ]
    for i, t in enumerate(patterns):
        items.append(("common_patterns", f"pat_{i}", t))

    code = {
        "python": '"""A normal Python module."""\nimport os\n\ndef fib(n: int) -> int:\n    return n if n <= 1 else fib(n-1)+fib(n-2)\n',
        "json": json.dumps({"name": "my-project", "version": "1.0.0", "deps": {"express": "^4.18.0"}}, indent=2),
        "html": "<!DOCTYPE html><html><body><h1>Welcome</h1><p>Normal page content.</p></body></html>",
        "sql": "CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) NOT NULL);\nSELECT 1;\n",
        "yaml": 'version: "3.8"\nservices:\n  web:\n    build: .\n    ports: ["8080:8080"]\n',
        "markdown": "# API Guide\n\nUse `curl` against https://api.example.com.\n",
    }
    for name, t in code.items():
        items.append(("code_inline", name, t))

    edge = [
        ("empty", ""),
        ("single_char", "A"),
        ("numbers", "123456789"),
        ("whitespace", "   \n\n   \t\t   "),
        ("long_word", "a" * 5000),
        ("base64_bearer", "Set header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        ("math", "The equation x + y = z holds. Given f(x) = 2x + 3, find f(5)."),
    ]
    for name, t in edge:
        items.append(("edge", name, t))

    return items


def cases_files() -> list[tuple[str, str, str]]:
    """(category, name, content) for temp files."""
    return [
        ("file_scan", ".py", "import os\nprint('hello')\n"),
        ("file_scan", ".js", "const x = 42;\nconsole.log(x);\n"),
        ("file_scan", ".json", '{"name": "test", "version": "1.0"}\n'),
        ("file_scan", ".txt", "Just a normal text file with nothing special.\n"),
        ("file_scan", ".md", "# Title\n\nSome text.\n"),
        ("file_scan", ".csv", "name,age\nAlice,30\nBob,25\n"),
    ]


def run_suite() -> dict:
    started = time.perf_counter()
    results: list[CaseResult] = []

    for category, name, text in cases_text():
        try:
            report = scan_text(text)
            clean = bool(getattr(report, "clean", False))
            results.append(
                CaseResult(
                    category=category,
                    name=name,
                    clean=clean,
                    findings=[] if clean else _findings(report),
                )
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                CaseResult(category=category, name=name, clean=False, error=str(exc))
            )

    for category, ext, content in cases_files():
        path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w", encoding="utf-8") as fh:
                fh.write(content)
                path = Path(fh.name)
            report = scan_file(path)
            clean = bool(getattr(report, "clean", False))
            results.append(
                CaseResult(
                    category=category,
                    name=f"file{ext}",
                    clean=clean,
                    findings=[] if clean else _findings(report),
                )
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                CaseResult(category=category, name=f"file{ext}", clean=False, error=str(exc))
            )
        finally:
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

    # optional clean PNG structural check
    try:
        import io

        import numpy as np
        from PIL import Image

        img = np.zeros((64, 64, 3), dtype=np.uint8)
        img[:, :] = [120, 140, 180]
        buf = io.BytesIO()
        Image.fromarray(img).save(buf, format="PNG")
        report = scan(buf.getvalue())
        structural_methods = {
            "trailing_data_after_eof",
            "polyglot_file",
            "embedded_file",
            "png_ancillary_chunks",
            "metadata_exif_hiding",
        }
        bad = [
            f
            for f in getattr(report, "findings", []) or []
            if getattr(getattr(f, "method", None), "value", "") in structural_methods
        ]
        results.append(
            CaseResult(
                category="image",
                name="clean_png_structural",
                clean=len(bad) == 0,
                findings=[str(x) for x in bad],
            )
        )
    except Exception as exc:  # noqa: BLE001
        results.append(
            CaseResult(category="image", name="clean_png_structural", clean=True, error=f"skipped: {exc}")
        )

    total = len(results)
    fps = [r for r in results if not r.clean and not (r.error and r.error.startswith("skipped"))]
    errors = [r for r in results if r.error and not r.error.startswith("skipped")]
    skipped = [r for r in results if r.error and r.error.startswith("skipped")]
    fp_rate = (len(fps) / total) if total else 0.0
    elapsed = time.perf_counter() - started

    by_cat: dict[str, dict[str, int]] = {}
    for r in results:
        bucket = by_cat.setdefault(r.category, {"total": 0, "fp": 0, "error": 0})
        bucket["total"] += 1
        if r.error and not r.error.startswith("skipped"):
            bucket["error"] += 1
        elif not r.clean:
            bucket["fp"] += 1

    payload = {
        "suite": "false_positive_suite",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_cases": total,
        "false_positives": len(fps),
        "errors": len(errors),
        "skipped": len(skipped),
        "false_positive_rate": round(fp_rate, 6),
        "pass": len(fps) == 0 and len(errors) == 0,
        "elapsed_seconds": round(elapsed, 3),
        "by_category": by_cat,
        "failures": [asdict(r) for r in fps + errors],
        "cases": [asdict(r) for r in results],
    }
    return payload


def write_outputs(payload: dict) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = RESULTS_DIR / f"false-positive-{ts}.json"
    latest_json = RESULTS_DIR / "false-positive-latest.json"
    md_path = RESULTS_DIR / f"false-positive-{ts}.md"
    latest_md = RESULTS_DIR / "false-positive-latest.md"

    text = json.dumps(payload, indent=2)
    json_path.write_text(text, encoding="utf-8")
    latest_json.write_text(text, encoding="utf-8")

    lines = [
        "# StegOFF false-positive suite",
        "",
        f"- Generated: `{payload['generated_at']}`",
        f"- Cases: **{payload['total_cases']}**",
        f"- False positives: **{payload['false_positives']}**",
        f"- Errors: **{payload['errors']}**",
        f"- FP rate: **{payload['false_positive_rate']:.4%}**",
        f"- Pass: **{payload['pass']}**",
        f"- Elapsed: {payload['elapsed_seconds']}s",
        "",
        "## By category",
        "",
        "| Category | Total | FP | Errors |",
        "|---|---:|---:|---:|",
    ]
    for cat, stats in sorted(payload["by_category"].items()):
        lines.append(f"| {cat} | {stats['total']} | {stats['fp']} | {stats['error']} |")
    lines.append("")
    if payload["failures"]:
        lines.append("## Failures")
        lines.append("")
        for f in payload["failures"]:
            lines.append(f"- **{f['category']}/{f['name']}**: clean={f['clean']} findings={f.get('findings')} error={f.get('error')}")
        lines.append("")
    else:
        lines.append("## Failures")
        lines.append("")
        lines.append("None.")
        lines.append("")

    md = "\n".join(lines)
    md_path.write_text(md, encoding="utf-8")
    latest_md.write_text(md, encoding="utf-8")
    return latest_json, latest_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="StegOFF false-positive suite")
    parser.add_argument("--json-only", action="store_true")
    args = parser.parse_args(argv)
    payload = run_suite()
    latest_json, latest_md = write_outputs(payload)
    if not args.json_only:
        print(latest_md.read_text(encoding="utf-8"))
        print(f"Wrote {latest_json}")
        print(f"Wrote {latest_md}")
    else:
        print(json.dumps({k: payload[k] for k in ("pass", "total_cases", "false_positives", "false_positive_rate")}, indent=2))
    return 0 if payload["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
