"""Deterministic fingerprint of the source and configuration that produced evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_INPUTS = (
    "gateway",
    "harness",
    "fixtures",
    "scripts",
    "config",
    "policies",
    "pyproject.toml",
    "uv.lock",
)


def source_fingerprint() -> str:
    digest = hashlib.sha256()
    files: list[Path] = []
    for name in SOURCE_INPUTS:
        path = ROOT / name
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and "__pycache__" not in candidate.parts
                and candidate.suffix not in {".pyc", ".pyo"}
            )
    for path in sorted(files, key=lambda item: item.relative_to(ROOT).as_posix()):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\n")
    return digest.hexdigest()


__all__ = ["source_fingerprint"]
