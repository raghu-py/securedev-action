from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .models import Severity


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    "coverage",
    "htmlcov",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "tmp",
    "temp",
    "logs",
}

DEFAULT_EXCLUDE_GLOBS = {
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.rar",
    "*.7z",
    "*.gz",
    "*.bz2",
    "*.xz",
    "*.mp4",
    "*.mov",
    "*.mp3",
    "*.wav",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.eot",
    "*.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
}

DEFAULT_INCLUDE_GLOBS = {"**/*"}


@dataclass(frozen=True)
class ScanConfig:
    root: Path
    output_dir: Path
    include_globs: tuple[str, ...] = tuple(DEFAULT_INCLUDE_GLOBS)
    exclude_globs: tuple[str, ...] = tuple(DEFAULT_EXCLUDE_GLOBS)
    exclude_dirs: tuple[str, ...] = tuple(DEFAULT_EXCLUDE_DIRS)
    max_file_size_bytes: int = 1024 * 1024
    fail_on: Severity | None = Severity.CRITICAL
    output_formats: tuple[str, ...] = ("json", "sarif", "markdown")
    show_snippets: bool = True
    annotations: bool = True


def parse_bool(raw: str | bool | None, default: bool = False) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    return default


def parse_csv(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return tuple()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def parse_output_formats(raw: str | None) -> tuple[str, ...]:
    values = {part.lower() for part in parse_csv(raw or "all")}
    if not values or "all" in values:
        return ("json", "sarif", "markdown")
    allowed = {"json", "sarif", "markdown", "md"}
    unknown = values - allowed
    if unknown:
        raise ValueError(f"Unsupported output format(s): {', '.join(sorted(unknown))}")
    normalized = []
    for value in values:
        normalized.append("markdown" if value == "md" else value)
    return tuple(sorted(set(normalized)))


def parse_fail_on(raw: str | None) -> Severity | None:
    value = (raw or "critical").strip().lower()
    if value in {"", "none", "never", "false", "off"}:
        return None
    severity = Severity.parse(value)
    if severity is None:
        raise ValueError("Invalid fail-on value. Use one of: critical, high, medium, low, none.")
    return severity
