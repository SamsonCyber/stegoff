"""
StegOFF CLI — scan text/files for stego, prompt injection, and related threats.

Common usage (no subcommand needed):
    stegoff suspicious.png
    stegoff "paste text here"
    echo "text" | stegoff -
    stegoff clean user_input.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from stegoff.orchestrator import scan_text, scan_file
from stegoff.report import ScanReport

_KNOWN = {
    "scan",
    "check",
    "scan-text",
    "scan-dir",
    "clean",
    "guard",
    "trap",
    "scan-html",
    "help",
    "-h",
    "--help",
}


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Bare invocation -> short help
    if not argv or argv[0] in ("help", "-h", "--help"):
        _print_quick_help()
        sys.exit(0 if not argv or argv[0] in ("-h", "--help", "help") else 0)

    # Smart default: "stegoff <path|text|->" without a subcommand
    if argv[0] not in _KNOWN and not argv[0].startswith("-"):
        argv = ["scan", *argv]

    parser = argparse.ArgumentParser(
        prog="stegoff",
        description=(
            "Detect and strip steganography / prompt injection before content "
            "hits an LLM or agent."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  stegoff note.txt\n"
            "  stegoff \"Ignore previous instructions\"\n"
            "  stegoff clean note.txt > clean.txt\n"
            "  cat msg.txt | stegoff guard --block\n"
        ),
    )
    sub = parser.add_subparsers(dest="command")

    # scan / check (aliases)
    for name, help_ in (
        ("scan", "Scan a file or free-text string"),
        ("check", "Alias for scan"),
    ):
        p = sub.add_parser(name, help=help_)
        p.add_argument(
            "target",
            help='File path, "-" for stdin, or a text string',
        )
        p.add_argument("--json", action="store_true", help="JSON output")
        p.add_argument(
            "--quiet",
            action="store_true",
            help="Print nothing when clean",
        )

    # scan-text (kept for scripts)
    p = sub.add_parser("scan-text", help="Scan a text string (or stdin)")
    p.add_argument("text", nargs="?", help="Text (stdin if omitted)")
    p.add_argument("--json", action="store_true")

    # scan-dir
    p = sub.add_parser("scan-dir", help="Scan files in a directory")
    p.add_argument("directory")
    p.add_argument("--json", action="store_true")
    p.add_argument("-r", "--recursive", action="store_true", default=True)
    p.add_argument("-e", "--extensions", nargs="+")

    # clean: scan + strip, print clean text
    p = sub.add_parser(
        "clean",
        help="Strip stego / hidden chars; print cleaned text",
    )
    p.add_argument(
        "target",
        nargs="?",
        default="-",
        help='File path, text, or "-" for stdin (default)',
    )

    # guard: pipeline filter (stdin)
    p = sub.add_parser(
        "guard",
        help="Read stdin; strip (default) or --block if dirty",
    )
    p.add_argument("--block", action="store_true", help="Exit 2 if dirty")
    p.add_argument(
        "--strip",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )

    # scan-html
    p = sub.add_parser("scan-html", help="Scan HTML for hidden content injection")
    p.add_argument("target", nargs="?", help="HTML file (stdin if omitted)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sanitize", action="store_true", help="Print cleaned HTML")

    # trap (advanced)
    p = sub.add_parser("trap", help="Run agent-trap battery (advanced)")
    p.add_argument(
        "-c",
        "--category",
        choices=[
            "content_injection",
            "semantic_manipulation",
            "cognitive_state",
            "behavioral_control",
            "systemic",
            "human_in_loop",
            "all",
        ],
        default="all",
    )
    p.add_argument("--json", action="store_true")
    p.add_argument("--llm", action="store_true")

    args = parser.parse_args(argv)

    if not args.command:
        _print_quick_help()
        sys.exit(1)

    if args.command in ("scan", "check"):
        _handle_scan_smart(args)
    elif args.command == "scan-text":
        _handle_scan_text(args)
    elif args.command == "scan-dir":
        _handle_scan_dir(args)
    elif args.command == "clean":
        _handle_clean(args)
    elif args.command == "guard":
        _handle_guard(args)
    elif args.command == "trap":
        _handle_trap(args)
    elif args.command == "scan-html":
        _handle_scan_html(args)
    else:
        _print_quick_help()
        sys.exit(1)


def _print_quick_help() -> None:
    print(
        """stegoff — detect stego + prompt injection before content hits an LLM

Quick start
  stegoff note.txt                 scan a file
  stegoff "paste text here"        scan free text
  stegoff -                        scan stdin
  stegoff clean note.txt           print cleaned text
  cat msg | stegoff guard --block  exit 2 if dirty

Also: scan-dir, scan-html, trap (advanced). Use --json for machine output.
Exit codes: 0 clean, 2 findings, 1 usage/error.
Full help: stegoff scan --help
"""
    )


def _resolve_target(target: str) -> tuple[str, ScanReport]:
    """Return (label, report) for a path, stdin, or free-text string."""
    if target == "-":
        text = sys.stdin.read()
        return "stdin", scan_text(text, source="stdin")

    path = Path(target)
    if path.is_file():
        return str(path), scan_file(path)

    # Free text (not an existing file)
    return "<text>", scan_text(target, source="<text>")


def _handle_scan_smart(args) -> None:
    label, report = _resolve_target(args.target)
    # Keep target label consistent in summary
    report.target = label
    _output_report(report, args.json, getattr(args, "quiet", False))
    sys.exit(0 if report.clean else 2)


def _handle_scan_text(args) -> None:
    text = args.text if args.text is not None else sys.stdin.read()
    report = scan_text(text)
    _output_report(report, args.json)
    sys.exit(0 if report.clean else 2)


def _handle_scan_dir(args) -> None:
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory", file=sys.stderr)
        sys.exit(1)

    pattern = "**/*" if args.recursive else "*"
    extensions = set(args.extensions) if args.extensions else None
    total_findings = 0
    scanned = 0

    for filepath in sorted(directory.glob(pattern)):
        if not filepath.is_file():
            continue
        if extensions and filepath.suffix not in extensions:
            continue
        try:
            report = scan_file(filepath)
            scanned += 1
            if not report.clean:
                total_findings += report.finding_count
                if args.json:
                    print(report.to_json())
                else:
                    print(report.summary())
                    print()
        except Exception as e:
            print(f"Error scanning {filepath}: {e}", file=sys.stderr)

    print(
        f"\nScanned {scanned} files, {total_findings} total findings",
        file=sys.stderr,
    )
    sys.exit(0 if total_findings == 0 else 2)


def _handle_clean(args) -> None:
    """Print cleaned text to stdout; findings summary on stderr if dirty."""
    from stegoff.sanitizers.text import sanitize_text

    target = args.target
    if target == "-":
        raw = sys.stdin.read()
        source = "stdin"
    else:
        path = Path(target)
        if path.is_file():
            raw = path.read_text(encoding="utf-8", errors="replace")
            source = str(path)
        else:
            raw = target
            source = "<text>"

    report = scan_text(raw, source=source)
    clean, _ = sanitize_text(raw)
    if not report.clean:
        print(report.summary(), file=sys.stderr)
    print(clean, end="" if clean.endswith("\n") or not clean else "\n")
    sys.exit(0 if report.clean else 2)


def _handle_guard(args) -> None:
    text = sys.stdin.read()
    report = scan_text(text, source="stdin")

    if report.clean:
        print(text, end="")
        sys.exit(0)

    print(report.summary(), file=sys.stderr)

    if args.block:
        print("BLOCKED: findings detected", file=sys.stderr)
        sys.exit(2)

    from stegoff.sanitizers.text import sanitize_text

    clean, _ = sanitize_text(text)
    print(clean, end="")
    sys.exit(0)


def _handle_trap(args) -> None:
    from stegoff.traps.base import TrapCategory
    from stegoff.traps.runner import TrapRunner

    runner = TrapRunner(use_llm=args.llm)
    if args.category == "all":
        battery = runner.run_all()
    else:
        battery = runner.run_category(TrapCategory(args.category))

    if args.json:
        print(battery.to_json())
    else:
        battery.print_report()
    sys.exit(0 if battery.total_bypassed == 0 else 1)


def _handle_scan_html(args) -> None:
    from stegoff.detectors.trapsweep import scan_html_traps, sanitize_html_traps

    if args.target:
        path = Path(args.target)
        if not path.exists():
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(1)
        html_content = path.read_text(encoding="utf-8", errors="replace")
        source = str(path)
    else:
        html_content = sys.stdin.read()
        source = "stdin"

    if args.sanitize:
        clean, ops = sanitize_html_traps(html_content)
        print(clean)
        if ops:
            print(f"\nOperations: {', '.join(ops)}", file=sys.stderr)
        sys.exit(0)

    findings = scan_html_traps(html_content, source=source)
    if not findings:
        if not args.json:
            print(f"[CLEAN] {source} - no content injection traps detected")
        else:
            print('{"clean": true, "findings": []}')
        sys.exit(0)

    if args.json:
        import json

        print(
            json.dumps(
                {
                    "clean": False,
                    "finding_count": len(findings),
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
            )
        )
    else:
        for f in findings:
            print(f"[{f.severity.name}] {f.description}")
            if f.evidence:
                print(f"  evidence: {f.evidence[:200]}")
    sys.exit(2)


def _output_report(
    report: ScanReport, as_json: bool = False, quiet: bool = False
) -> None:
    if as_json:
        print(report.to_json())
        return
    if quiet and report.clean:
        return
    print(report.summary())


if __name__ == "__main__":
    main()
