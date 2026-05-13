from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import (
    DEFAULT_EXCLUDE_GLOBS,
    ScanConfig,
    parse_bool,
    parse_csv,
    parse_fail_on,
    parse_output_formats,
)
from .reporters import emit_annotations, set_github_outputs, write_reports, write_step_summary
from .scanner import SecureDevScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securedev-action",
        description="Self-contained security scanner for GitHub Actions.",
    )
    parser.add_argument("--path", default=".", help="Path to scan.")
    parser.add_argument(
        "--fail-on",
        default="critical",
        help="Minimum severity that fails the run: critical, high, medium, low, none.",
    )
    parser.add_argument("--output-dir", default="securedev-results", help="Directory for reports.")
    parser.add_argument("--output-format", default="all", help="all, json, sarif, markdown, or comma-separated list.")
    parser.add_argument("--include", default="", help="Comma-separated include glob patterns.")
    parser.add_argument("--exclude", default="", help="Comma-separated exclude glob patterns.")
    parser.add_argument("--max-file-size-kb", default="1024", help="Maximum file size to scan in KB.")
    parser.add_argument("--show-snippets", default="true", help="Include snippets in reports: true or false.")
    parser.add_argument("--annotations", default="true", help="Emit GitHub annotations: true or false.")
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    try:
        root = _resolve_action_path(args.path)
        if not root.exists():
            raise ValueError(f"Scan path does not exist: {args.path}")

        max_file_size_kb = int(args.max_file_size_kb)
        if max_file_size_kb < 1:
            raise ValueError("max-file-size-kb must be at least 1")

        include = parse_csv(args.include) or ("**/*",)
        extra_exclude = parse_csv(args.exclude)
        output_formats = parse_output_formats(args.output_format)
        fail_on = parse_fail_on(args.fail_on)

        config = ScanConfig(
            root=root,
            output_dir=_resolve_action_path(args.output_dir),
            include_globs=include,
            exclude_globs=tuple(sorted(set(DEFAULT_EXCLUDE_GLOBS).union(extra_exclude))),
            max_file_size_bytes=max_file_size_kb * 1024,
            fail_on=fail_on,
            output_formats=output_formats,
            show_snippets=parse_bool(args.show_snippets, default=True),
            annotations=parse_bool(args.annotations, default=True),
        )
    except Exception as exc:
        print(f"securedev-action configuration error: {exc}", file=sys.stderr)
        return 2

    print("SecureDev Action by Raghu Soni")
    print(f"Version: {__version__}")
    print(f"Scan path: {config.root}")
    print(f"Fail on: {config.fail_on.label if config.fail_on else 'none'}")
    print(f"Output formats: {', '.join(config.output_formats)}")

    scanner = SecureDevScanner(config)
    summary = scanner.scan()
    counts = summary.counts_by_severity()

    report_paths = write_reports(
        summary=summary,
        output_dir=config.output_dir,
        formats=config.output_formats,
        include_snippets=config.show_snippets,
    )

    result = "fail" if summary.should_fail(config.fail_on) else "pass"

    print("\nScan complete")
    print(f"Scanned files: {summary.scanned_files}")
    print(f"Skipped files: {summary.skipped_files}")
    print(f"Findings: {len(summary.findings)}")
    print(
        "Severity counts: "
        f"critical={counts['critical']}, high={counts['high']}, "
        f"medium={counts['medium']}, low={counts['low']}, info={counts['info']}"
    )

    for kind, path in sorted(report_paths.items()):
        print(f"{kind} report: {path}")

    if config.annotations:
        emit_annotations(summary)

    write_step_summary(summary, report_paths)
    set_github_outputs(summary, report_paths, result)

    if result == "fail":
        print("SecureDev Action failed because findings met or exceeded the configured fail-on severity.", file=sys.stderr)
        return 1

    print("SecureDev Action passed.")
    return 0


def _resolve_action_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    workspace = os.getenv("GITHUB_WORKSPACE")
    if workspace:
        return (Path(workspace) / path).resolve()
    return path.resolve()


if __name__ == "__main__":
    raise SystemExit(main())
