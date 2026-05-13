from __future__ import annotations

from .config import ScanConfig
from .filewalker import FileWalker, SkippedFile, SourceFile
from .models import ScanSummary
from .rules import scan_text


class SecureDevScanner:
    """Coordinates file discovery and rule execution."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def scan(self) -> ScanSummary:
        summary = ScanSummary()
        walker = FileWalker(self.config)

        for item in walker.walk():
            if isinstance(item, SkippedFile):
                summary.skipped_files += 1
                summary.skipped_reasons[item.reason] = summary.skipped_reasons.get(item.reason, 0) + 1
                continue
            if isinstance(item, SourceFile):
                summary.scanned_files += 1
                summary.bytes_scanned += item.size_bytes
                summary.findings.extend(scan_text(item.relative_path, item.content))

        summary.findings.sort(key=lambda f: (-int(f.severity), f.file_path, f.line, f.rule_id))
        return summary
