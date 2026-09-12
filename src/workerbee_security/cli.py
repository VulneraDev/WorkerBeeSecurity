import argparse
import sys
from typing import List, Optional

from . import __version__
from .analysis import analyze
from .enrichment import EnrichmentError, enrich
from .parser import CowrieParseError, parse_file
from .reporting import write_reports


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="workerbee",
        description="Turn Cowrie logs into analyst-ready reports.",
    )
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    analyze_command = commands.add_parser("analyze", help="analyze a Cowrie JSONL log")
    analyze_command.add_argument("input", help="path to cowrie.json, or - for stdin")
    analyze_command.add_argument(
        "-o", "--output", default="workerbee-report", help="report output directory"
    )
    analyze_command.add_argument(
        "-f",
        "--format",
        action="append",
        choices=("markdown", "json", "csv"),
        dest="formats",
        help="output format; repeat to select multiple (default: all)",
    )
    analyze_command.add_argument(
        "--enrich",
        action="append",
        choices=("abuseipdb", "virustotal"),
        default=[],
        help="passive enrichment provider; requires its API key environment variable",
    )
    analyze_command.add_argument("--max-enrich", type=int, default=25)
    analyze_command.add_argument("--timeout", type=float, default=10.0)
    analyze_command.add_argument("--limit", type=int)
    analyze_command.add_argument("--max-line-bytes", type=int, default=2_000_000)
    analyze_command.add_argument("--strict", action="store_true")
    analyze_command.add_argument(
        "--redact-credentials",
        action="store_true",
        help="replace attempted passwords with <redacted> in reports",
    )
    analyze_command.add_argument(
        "--show-credentials",
        action="store_false",
        dest="redact_credentials",
        help=argparse.SUPPRESS,
    )
    analyze_command.set_defaults(redact_credentials=False)
    return root


def run(argv: Optional[List[str]] = None) -> int:
    args = parser().parse_args(argv)
    if args.max_enrich < 1 or args.timeout <= 0 or args.max_line_bytes < 1:
        print("workerbee: numeric limits must be greater than zero", file=sys.stderr)
        return 2
    if args.limit is not None and args.limit < 1:
        print("workerbee: --limit must be greater than zero", file=sys.stderr)
        return 2

    try:
        result = parse_file(
            args.input,
            strict=args.strict,
            limit=args.limit,
            max_line_bytes=args.max_line_bytes,
        )
        report = analyze(result, show_credentials=not args.redact_credentials)
        if args.enrich:
            report["summary"]["enrichment_queries"] = enrich(
                report["indicators"], args.enrich, args.max_enrich, args.timeout
            )
        paths = write_reports(report, args.output, args.formats or ("markdown", "json", "csv"))
    except (CowrieParseError, EnrichmentError, OSError, ValueError) as exc:
        print(f"workerbee: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print(
        f"Analyzed {summary['events']} events across {summary['sessions']} sessions; "
        f"found {summary['indicators']} indicators."
    )
    for path in paths:
        print(path)
    return 0


def main() -> None:
    raise SystemExit(run())
