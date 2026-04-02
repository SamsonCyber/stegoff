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
