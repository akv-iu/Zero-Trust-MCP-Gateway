"""ROUTE-003: the router must have no I/O capability of its own.

If `gateway/router.py` can touch the filesystem or the network directly, the
gateway's mediation claim is void — a bug there could produce a side effect without
passing a policy decision.

AST-based rather than grep-based: a text search trips over its own docstring and
misses aliased imports. This runs in the normal suite, so no CI wiring is needed.
A legitimate need to relax it is a design conversation, which is what a failure forces.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROUTER = Path(__file__).resolve().parents[2] / "gateway" / "router.py"

FORBIDDEN_MODULES = {
    "os", "os.path", "io", "pathlib", "shutil", "tempfile", "glob",
    "socket", "ssl", "subprocess", "httpx", "requests", "urllib", "aiohttp",
}
FORBIDDEN_CALLS = {"open", "exec", "eval", "compile", "__import__"}


def _tree() -> ast.Module:
    return ast.parse(ROUTER.read_text("utf-8"), filename=str(ROUTER))


def test_router_imports_no_io_modules() -> None:
    found: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    assert not (found & FORBIDDEN_MODULES), (
        f"ROUTE-003 violation: gateway/router.py imports {sorted(found & FORBIDDEN_MODULES)}"
    )


def test_router_calls_no_io_builtins() -> None:
    bad = [
        node.func.id
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in FORBIDDEN_CALLS
    ]
    assert not bad, f"ROUTE-003 violation: gateway/router.py calls {sorted(set(bad))}"


def test_the_check_would_actually_fire(tmp_path: Path) -> None:
    """Negative control. A check that cannot fail is not a check."""
    sample = tmp_path / "bad.py"
    sample.write_text("import socket\nopen('/etc/passwd')\n", encoding="utf-8")
    tree = ast.parse(sample.read_text("utf-8"))
    mods = {
        a.name.split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, ast.Import)
        for a in n.names
    }
    calls = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert mods & FORBIDDEN_MODULES
    assert calls & FORBIDDEN_CALLS


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
