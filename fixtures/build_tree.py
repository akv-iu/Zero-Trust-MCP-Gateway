"""Build, reset, and hash the fixture tree.

FIX-009: reset must be *verified*, not assumed. A corpus that depends on scenario
ordering is not reproducible, and the dependency will not be obvious when it appears.

Deliberately imports nothing from `gateway.*` (FIX / TECH-10 §8). `tree_hash` is
duplicated rather than shared: if a gateway bug and an oracle bug shared an
implementation, they would mask each other.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

from fixtures.manifest import LINKS, TREE


class SymlinksUnavailable(RuntimeError):
    """The platform refused symlink creation (Windows without Developer Mode)."""


def build(root: Path, *, strict_links: bool = False) -> str:
    """Create the tree at `root`. Returns its hash.

    `strict_links=True` raises SymlinksUnavailable instead of degrading, so a test
    run can choose between "skip the symlink scenarios" and "fail loudly".
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    for rel, content in TREE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")

    for rel, target in LINKS.items():
        link = root / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            _unlink(link)
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as e:
            if strict_links:
                raise SymlinksUnavailable(f"cannot create {rel} -> {target}") from e
            # Degrade honestly: the trap is absent, and links_available() says so.
            continue

    return tree_hash(root)


def links_available(root: Path) -> bool:
    """Whether the trap symlinks exist. Scenarios that need them SKIP when False."""
    return all((Path(root) / rel).is_symlink() for rel in LINKS)


def reset(root: Path) -> str:
    """Restore to a known state. Returns the hash so the caller can verify it."""
    root = Path(root)
    if root.exists():
        shutil.rmtree(root, onexc=_force_remove)
    return build(root)


def tree_hash(root: Path) -> str:
    """Hash path + mode + content, and link targets for symlinks.

    Mode and link targets are included deliberately: a permission change or a
    retargeted symlink is a side effect that content-only hashing would miss.
    """
    h = hashlib.sha256()
    root = Path(root)
    if not root.exists():
        return "absent"
    for p in sorted(root.rglob("*"), key=lambda q: q.as_posix()):
        rel = p.relative_to(root).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        if p.is_symlink():
            h.update(b"link:")
            h.update(os.readlink(p).replace("\\", "/").encode("utf-8"))
        elif p.is_dir():
            h.update(b"dir:")
        else:
            h.update(b"file:")
            # Mode is normalised to the executable bit only — Windows and POSIX
            # disagree on the rest, and that noise would break cross-platform hashes.
            h.update(b"x" if os.access(p, os.X_OK) and os.name != "nt" else b"-")
            h.update(p.read_bytes())
        h.update(b"\n")
    return h.hexdigest()


def _unlink(p: Path) -> None:
    try:
        p.unlink()
    except (IsADirectoryError, PermissionError, OSError):
        shutil.rmtree(p, ignore_errors=True)


def _force_remove(func, path, exc):  # noqa: ANN001 - shutil.rmtree onexc signature
    """Windows leaves read-only files undeletable; clear the bit and retry."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


if __name__ == "__main__":  # pragma: no cover
    target = Path(os.environ.get("FIXTURE_ROOT", "var/fixture"))
    print(f"{target}: {build(target)}  links={links_available(target)}")
