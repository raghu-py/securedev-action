from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .models import Finding, Rule, ScanSummary, Severity
from .rules import all_rules


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def write_reports(summary: ScanSummary, output_dir: Path, formats: tuple[str, ...], include_snippets: bool) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    if "json" in formats:
        path = output_dir / "securedev-report.json"
        path.write_text(json.dumps(json_report(summary, include_snippets), indent=2), encoding="utf-8")
        paths["json"] = str(path)

    if "sarif" in formats:
        path = output_dir / "securedev-report.sarif"
        path.write_text(json.dumps(sarif_report(summary), indent=2), encoding="utf-8")
        paths["sarif"] = str(path)

    if "markdown" in formats:
        path = output_dir / "securedev-summary.md"
        path.write_text(markdown_report(summary, include_snippets), encoding="utf-8")
        paths["markdown"] = str(path)

    return paths


def json_report(summary: ScanSummary, include_snippets: bool) -> dict[str, Any]:
    return {
        "tool": {
            "name": "SecureDev Action",
            "version": __version__,
            "author": "Raghu Soni",
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "scanned_files": summary.scanned_files,
            "skipped_files": summary.skipped_files,
            "bytes_scanned": summary.bytes_scanned,
            "findings_count": len(summary.findings),
            "counts_by_severity": summary.counts_by_severity(),
            "skipped_reasons": summary.skipped_reasons,
        },
        "findings": [finding.to_dict(include_snippet=include_snippets) for finding in summary.findings],
    }


def sarif_report(summary: ScanSummary) -> dict[str, Any]:
    rules = [_sarif_rule(rule) for rule in all_rules()]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureDev Action",
                        "informationUri": "https://github.com/raghu-py/securedev-action",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "securedev-action"},
                "results": [_sarif_result(finding) for finding in summary.findings],
            }
        ],
    }


def markdown_report(summary: ScanSummary, include_snippets: bool) -> str:
    counts = summary.counts_by_severity()
    status = "FAIL" if counts["critical"] else "PASS"
    lines = [
        "# SecureDev Security Scan",
        "",
        f"**Status:** {status}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Scanned files | {summary.scanned_files} |",
        f"| Skipped files | {summary.skipped_files} |",
        f"| Bytes scanned | {summary.bytes_scanned} |",
        f"| Total findings | {len(summary.findings)} |",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        f"| Info | {counts['info']} |",
        "",
    ]

    if summary.skipped_reasons:
        lines.extend(["## Skipped Files", "", "| Reason | Count |", "|---|---:|"])
        for reason, count in sorted(summary.skipped_reasons.items()):
            lines.append(f"| {reason} | {count} |")
        lines.append("")

    if not summary.findings:
        lines.extend(["## Findings", "", "No findings detected.", ""])
        return "\n".join(lines)

    lines.extend(["## Findings", ""])
    for severity in SEVERITY_ORDER:
        group = [finding for finding in summary.findings if finding.severity == severity]
        if not group:
            continue
        lines.extend([f"### {severity.label.title()} ({len(group)})", ""])
        for finding in group:
            lines.extend(_markdown_finding(finding, include_snippets))
    return "\n".join(lines)


def write_step_summary(summary: ScanSummary, report_paths: dict[str, str]) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    counts = summary.counts_by_severity()
    lines = [
        "## SecureDev Action",
        "",
        f"Scanned **{summary.scanned_files}** files and found **{len(summary.findings)}** issue(s).",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        f"| Info | {counts['info']} |",
        "",
    ]
    if report_paths:
        lines.extend(["### Reports", ""])
        for kind, path in sorted(report_paths.items()):
            lines.append(f"- {kind}: `{path}`")
        lines.append("")
    top_findings = summary.findings[:20]
    if top_findings:
        lines.extend(["### Top findings", ""])
        for finding in top_findings:
            lines.append(
                f"- **{finding.severity.label.upper()}** `{finding.rule_id}` "
                f"{finding.file_path}:{finding.line} - {finding.title}"
            )
        if len(summary.findings) > len(top_findings):
            lines.append(f"- ...and {len(summary.findings) - len(top_findings)} more finding(s).")
        lines.append("")
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def emit_annotations(summary: ScanSummary) -> None:
    for finding in summary.findings:
        command = "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
        title = _escape_annotation(f"{finding.rule_id}: {finding.title}")
        message = _escape_annotation(f"{finding.message} Recommendation: {finding.recommendation}")
        file_path = _escape_annotation(finding.file_path)
        print(f"::{command} file={file_path},line={finding.line},col={finding.column},title={title}::{message}")


def set_github_outputs(summary: ScanSummary, report_paths: dict[str, str], result: str) -> None:
    output_path = os.getenv("GITHUB_OUTPUT")
    if not output_path:
        return
    counts = summary.counts_by_severity()
    values = {
        "result": result,
        "findings_count": str(len(summary.findings)),
        "critical_count": str(counts["critical"]),
        "high_count": str(counts["high"]),
        "medium_count": str(counts["medium"]),
        "low_count": str(counts["low"]),
        "report_json": report_paths.get("json", ""),
        "report_sarif": report_paths.get("sarif", ""),
        "report_markdown": report_paths.get("markdown", ""),
    }
    with open(output_path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _sarif_rule(rule: Rule) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "category": rule.category,
        "precision": "medium",
        "security-severity": _security_severity(rule.severity),
        "tags": list(rule.tags),
    }
    if rule.cwe:
        properties["tags"] = list(dict.fromkeys([*properties["tags"], rule.cwe.lower()]))
    sarif_rule: dict[str, Any] = {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.message},
        "help": {"text": rule.recommendation, "markdown": rule.recommendation},
        "defaultConfiguration": {"level": rule.severity.sarif_level},
        "properties": properties,
    }
    if rule.help_uri:
        sarif_rule["helpUri"] = rule.help_uri
    return sarif_rule


def _sarif_result(finding: Finding) -> dict[str, Any]:
    result = {
        "ruleId": finding.rule_id,
        "level": finding.severity.sarif_level,
        "message": {"text": f"{finding.message} {finding.recommendation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
                    "region": {
                        "startLine": max(finding.line, 1),
                        "startColumn": max(finding.column, 1),
                    },
                }
            }
        ],
        "partialFingerprints": {"securedevFingerprint": finding.fingerprint},
        "properties": {
            "severity": finding.severity.label,
            "category": finding.category,
            "confidence": finding.confidence,
        },
    }
    if finding.cwe:
        result["properties"]["cwe"] = finding.cwe
    return result


def _markdown_finding(finding: Finding, include_snippets: bool) -> list[str]:
    lines = [
        f"#### `{finding.rule_id}` {finding.title}",
        "",
        f"- **Location:** `{finding.file_path}:{finding.line}:{finding.column}`",
        f"- **Category:** {finding.category}",
        f"- **Confidence:** {finding.confidence}",
    ]
    if finding.cwe:
        lines.append(f"- **CWE:** {finding.cwe}")
    lines.extend(
        [
            f"- **Issue:** {finding.message}",
            f"- **Fix:** {finding.recommendation}",
        ]
    )
    if include_snippets and finding.snippet:
        lines.extend(["", "```text", finding.snippet[:500], "```"])
    lines.append("")
    return lines


def _security_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.0",
        Severity.INFO: "0.0",
    }[severity]


def _escape_annotation(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(",", "%2C").replace(":", "%3A")
