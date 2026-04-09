"""
StegOFF CLI — scan files and text for hidden steganographic payloads.

Usage:
    stegoff scan <file>           Scan a file
    stegoff scan-text <text>      Scan a text string
    stegoff scan-dir <directory>  Scan all files in a directory
    stegoff guard                 Read stdin, strip steg, output clean text
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from stegoff.orchestrator import scan_text, scan_file
from stegoff.report import ScanReport


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='stegoff',
        description='Detect steganography and prompt injection payloads'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a file for steganography')
    scan_parser.add_argument('target', help='File path to scan')
    scan_parser.add_argument('--json', action='store_true', help='Output as JSON')
    scan_parser.add_argument('--quiet', action='store_true', help='Only output if findings detected')

    # scan-text command
    text_parser = subparsers.add_parser('scan-text', help='Scan text for steganography')
    text_parser.add_argument('text', nargs='?', help='Text to scan (reads stdin if omitted)')
    text_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # scan-dir command
    dir_parser = subparsers.add_parser('scan-dir', help='Scan all files in a directory')
    dir_parser.add_argument('directory', help='Directory to scan')
    dir_parser.add_argument('--json', action='store_true', help='Output as JSON')
    dir_parser.add_argument('--recursive', '-r', action='store_true', default=True,
                           help='Scan recursively (default)')
    dir_parser.add_argument('--extensions', '-e', nargs='+',
                           help='File extensions to scan (e.g., .png .jpg .txt)')

    # guard command
    guard_parser = subparsers.add_parser('guard',
        help='Read stdin, detect steg, output clean text (pipeline filter)')
    guard_parser.add_argument('--strip', action='store_true', default=True,
                             help='Strip detected steganographic content')
    guard_parser.add_argument('--block', action='store_true',
                             help='Block (exit 1) if steg detected instead of stripping')

    # trap command -- red team trap testing suite
    trap_parser = subparsers.add_parser('trap',
        help='Run agent trap battery tests against StegOFF defenses')
    trap_parser.add_argument('--category', '-c',
                            choices=['content_injection', 'semantic_manipulation',
                                     'cognitive_state', 'behavioral_control',
                                     'systemic', 'human_in_loop', 'all'],
                            default='all',
                            help='Trap category to test (default: all)')
    trap_parser.add_argument('--json', action='store_true',
                            help='Output results as JSON')
    trap_parser.add_argument('--llm', action='store_true',
                            help='Enable LLM-based detection (Layer 2)')

    # scan-html command -- HTML trap detection
    html_parser = subparsers.add_parser('scan-html',
        help='Scan HTML for content injection traps')
    html_parser.add_argument('target', nargs='?',
                            help='HTML file path (reads stdin if omitted)')
    html_parser.add_argument('--json', action='store_true',
                            help='Output as JSON')
    html_parser.add_argument('--sanitize', action='store_true',
                            help='Output sanitized HTML instead of scan report')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'scan':
        _handle_scan(args)
    elif args.command == 'scan-text':
        _handle_scan_text(args)
    elif args.command == 'scan-dir':
        _handle_scan_dir(args)
    elif args.command == 'guard':
        _handle_guard(args)
    elif args.command == 'trap':
        _handle_trap(args)
    elif args.command == 'scan-html':
        _handle_scan_html(args)


def _handle_scan(args):
    path = Path(args.target)
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr)
        sys.exit(1)

    report = scan_file(path)
    _output_report(report, args.json, getattr(args, 'quiet', False))
    sys.exit(0 if report.clean else 2)


def _handle_scan_text(args):
    if args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    report = scan_text(text)
    _output_report(report, args.json)
    sys.exit(0 if report.clean else 2)


def _handle_scan_dir(args):
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory", file=sys.stderr)
        sys.exit(1)

    pattern = '**/*' if args.recursive else '*'
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

    print(f"\nScanned {scanned} files, {total_findings} total findings", file=sys.stderr)
    sys.exit(0 if total_findings == 0 else 2)


def _handle_guard(args):
    """Pipeline filter: reads stdin, detects steg, outputs clean text."""
    text = sys.stdin.read()
    report = scan_text(text, source="stdin")

    if report.clean:
        print(text, end='')
        sys.exit(0)

    # Output findings to stderr
    print(report.summary(), file=sys.stderr)

    if args.block:
        print("BLOCKED: steganographic content detected", file=sys.stderr)
        sys.exit(2)

    # Strip mode: remove detected steganographic characters
    clean = _strip_steg_chars(text)
    print(clean, end='')
    sys.exit(0)


def _handle_trap(args):
    """Run the agent trap battery test suite."""
    from stegoff.traps.base import TrapCategory
    from stegoff.traps.runner import TrapRunner

    runner = TrapRunner(use_llm=args.llm)

    if args.category == 'all':
        battery = runner.run_all()
    else:
        cat = TrapCategory(args.category)
        battery = runner.run_category(cat)

    if args.json:
        print(battery.to_json())
    else:
        battery.print_report()

    # Exit code: 0 = all blocked, 1 = some bypassed
    sys.exit(0 if battery.total_bypassed == 0 else 1)


def _handle_scan_html(args):
    """Scan HTML for content injection traps."""
    from stegoff.detectors.trapsweep import scan_html_traps, sanitize_html_traps
    from stegoff.report import ScanReport

    if args.target:
        path = Path(args.target)
        if not path.exists():
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(1)
        html_content = path.read_text(encoding='utf-8', errors='replace')
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
            print(f"[CLEAN] {source} — no content injection traps detected")
        else:
            print('{"clean": true, "findings": []}')
        sys.exit(0)

    if args.json:
        import json
        print(json.dumps({
            "clean": False,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        for f in findings:
            print(f"[{f.severity.name}] {f.description}")
            if f.evidence:
                print(f"  evidence: {f.evidence[:200]}")
    sys.exit(2)


def _strip_steg_chars(text: str) -> str:
    """Remove known steganographic characters from text.
    Delegates to the canonical sanitizer in stegoff.sanitizers.text.
    """
    from stegoff.sanitizers.text import sanitize_text
    clean, _ = sanitize_text(text)
    return clean


def _output_report(report: ScanReport, as_json: bool = False, quiet: bool = False):
    if as_json:
        print(report.to_json())
    else:
        if quiet and report.clean:
            return
        print(report.summary())


if __name__ == '__main__':
    main()
