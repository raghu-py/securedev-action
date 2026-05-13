from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable

from .config import ScanConfig


@dataclass(frozen=True)
class SourceFile:
    path: Path
    relative_path: str
    content: str
    size_bytes: int


@dataclass(frozen=True)
class SkippedFile:
    path: Path
    relative_path: str
    reason: str


class FileWalker:
    """Discovers text-like files while avoiding noisy generated directories."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.root = config.root.resolve()

    def walk(self) -> Iterable[SourceFile | SkippedFile]:
        if self.root.is_file():
            yield from self._read_single(self.root)
            return

        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if self._is_under_excluded_dir(path):
                continue
            yield from self._read_single(path)

    def _read_single(self, path: Path) -> Iterable[SourceFile | SkippedFile]:
        rel = self._relative(path)
        if not self._included(rel):
            yield SkippedFile(path=path, relative_path=rel, reason="not_included")
            return
        if self._excluded(rel):
            yield SkippedFile(path=path, relative_path=rel, reason="excluded")
            return

        try:
            stat = path.stat()
        except OSError:
            yield SkippedFile(path=path, relative_path=rel, reason="stat_failed")
            return

        if stat.st_size > self.config.max_file_size_bytes:
            yield SkippedFile(path=path, relative_path=rel, reason="too_large")
            return

        try:
            raw = path.read_bytes()
        except OSError:
            yield SkippedFile(path=path, relative_path=rel, reason="read_failed")
            return

        if self._looks_binary(raw):
            yield SkippedFile(path=path, relative_path=rel, reason="binary")
            return

        content = self._decode(raw)
        if content is None:
            yield SkippedFile(path=path, relative_path=rel, reason="decode_failed")
            return

        yield SourceFile(path=path, relative_path=rel, content=content, size_bytes=stat.st_size)

    def _relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.name

    def _included(self, rel: str) -> bool:
        patterns = self.config.include_globs or ("**/*",)
        if any(p in {"*", "**", "**/*"} for p in patterns):
            return True
        return any(fnmatch(rel, p) or fnmatch(Path(rel).name, p) for p in patterns)

    def _excluded(self, rel: str) -> bool:
        return any(fnmatch(rel, p) or fnmatch(Path(rel).name, p) for p in self.config.exclude_globs)

    def _is_under_excluded_dir(self, path: Path) -> bool:
        try:
            rel_parts = path.resolve().relative_to(self.root).parts[:-1]
        except ValueError:
            rel_parts = path.parts[:-1]
        return any(part in self.config.exclude_dirs for part in rel_parts)

    @staticmethod
    def _looks_binary(raw: bytes) -> bool:
        if not raw:
            return False
        if b"\x00" in raw[:4096]:
            return True
        sample = raw[:4096]
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(32, 127)))
        non_text = sample.translate(None, text_chars)
        return len(non_text) / max(len(sample), 1) > 0.30

    @staticmethod
    def _decode(raw: bytes) -> str | None:
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return None
