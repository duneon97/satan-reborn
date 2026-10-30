"""Command-line entry point: python -m satan_reborn."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .report import render_html, write_json, write_text_atomic
from .scanner import scan
from .server import DEFAULT_REPORT, serve


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="satan_reborn",
        description="SATAN Reborn: read-only, offline-first local security auditing.",
    )
    parser.add_argument("--version", action="version", version=f"SATAN Reborn {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan", help="audit a local folder without running its code")
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--html", type=Path, help="also write the HTML report to this path")
    scan_parser.add_argument("--json", type=Path, help="write a machine-readable JSON report")
    scan_parser.add_argument(
        "--osv", action="store_true",
        help="opt in to sending pinned package names/versions to api.osv.dev (never source)",
    )
    serve_parser = subcommands.add_parser("serve", help="show the last report on loopback only")
    serve_parser.add_argument("--port", type=port_number, default=1995)
    serve_parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve(args.report, args.port)
            return 0
        outputs = [DEFAULT_REPORT]
        if args.html:
            outputs.append(args.html)
        if args.json:
            outputs.append(args.json)
        if args.json and any(
            args.json.expanduser().resolve() == path.expanduser().resolve()
            for path in outputs[:-1]
        ):
            raise ValueError("HTML and JSON output paths must be different.")
        report = scan(args.path, osv=args.osv, exclude_paths=outputs)
        html = render_html(report)
        for output in dict.fromkeys(path.expanduser().resolve() for path in outputs if path != args.json):
            write_text_atomic(output, html)
        if args.json:
            write_json(report, args.json)
        print(f"SATAN REBORN // {report.files_scanned} files examined")
        print(f"Soul Integrity: {report.soul_integrity}/100")
        print("  ".join(f"{s.value}={report.counts[s.value]}" for s in Severity))
        for finding in report.findings:
            # ascii() prevents malicious filenames from injecting terminal controls.
            location = ascii(f"{finding.file}:{finding.line}")
            print(f"[{finding.severity.value}/{finding.severity.standard}] {location} {finding.title}")
            print(f"  {finding.cwe} | Fix: {finding.advice}")
            if finding.evidence:
                print(f"  Evidence: {finding.evidence}")
        for warning in report.warnings:
            print(f"Warning: {ascii(warning)}", file=sys.stderr)
        print(f"Last HTML report: {DEFAULT_REPORT}")
        if args.html:
            print(f"HTML export: {ascii(str(args.html))}")
        if args.json:
            print(f"JSON export: {ascii(str(args.json))}")
        return 1 if report.has_blockers else 0
    except (OSError, ValueError):
        # Exception messages may contain credential-bearing paths or other raw input.
        print("SATAN Reborn: unable to complete the operation. Check the target directory, "
              "distinct output paths, permissions, and (for serve) the report and port.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
