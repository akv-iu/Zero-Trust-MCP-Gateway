"""Start OPA against `policies/rego`, wait for it to answer, tear it down.

    python -m scripts.opa_sidecar          # run in the foreground until Ctrl-C
    with sidecar() as base_url: ...        # what the tests use

Development and test tooling. **The gateway never launches OPA** — in a real
deployment the sidecar is somebody else's process, and a gateway that could start its
own policy engine could also restart one it had just found unhealthy, which is how
fail-closed turns into fail-eventually.

The binary is looked up in `$ZTMG_OPA_BIN`, then `.tools/`, then `PATH`. Version is
PINNED: Rego syntax differs between OPA 0.x and 1.x, and a bundle authored against one
fails or — worse — evaluates differently on the other.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Generator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "policies" / "rego"

PINNED_MAJOR = "1"
"""The Rego language version this bundle is written for. `import rego.v1` and the
bare `if`/`contains` keywords are 1.x; on 0.x the same files parse differently or not
at all, so the check is on the major version rather than being left to a runtime
surprise."""


def find_binary() -> Path | None:
    if override := os.environ.get("ZTMG_OPA_BIN"):
        p = Path(override)
        return p if p.exists() else None
    for candidate in (REPO / ".tools" / "opa.exe", REPO / ".tools" / "opa"):
        if candidate.exists():
            return candidate
    found = shutil.which("opa")
    return Path(found) if found else None


def version_of(binary: Path) -> str:
    out = subprocess.run(  # noqa: S603 - path comes from find_binary, not from input
        [str(binary), "version"], capture_output=True, text=True, timeout=60, check=False
    ).stdout
    for line in out.splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return ""


def _free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass(frozen=True)
class RunningSidecar:
    """A test-owned OPA process that can be terminated after gateway readiness."""

    base_url: str
    process: subprocess.Popen[bytes]

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - belt and braces
                self.process.kill()
                self.process.wait(timeout=10)


@contextmanager
def sidecar(port: int | None = None, bundle: Path = BUNDLE) -> Generator[str]:
    """Yield the base URL of a running OPA, or raise if one cannot be started.

    Binds `127.0.0.1` explicitly (REQ-SEC-012) — some OPA versions default to
    `0.0.0.0`, which would put an unauthenticated policy API on every interface.

    `--set decision_logs.console=false` matters for more than noise: OPA's decision
    logs echo the policy INPUT to its stdout, which carries the canonical path. The
    gateway's audit log is the record of what was decided; a second, unminimised copy
    on a child process's stdout is not something this project should be producing.
    """
    with controlled_sidecar(port=port, bundle=bundle) as running:
        yield running.base_url


@contextmanager
def controlled_sidecar(
    port: int | None = None, bundle: Path = BUNDLE
) -> Generator[RunningSidecar]:
    """Yield the process handle for chaos tests; production never calls this."""
    binary = find_binary()
    if binary is None:
        raise RuntimeError(
            "OPA not found. Set ZTMG_OPA_BIN, put it in .tools/, or install it on PATH."
        )
    version = version_of(binary)
    if not version.startswith(f"{PINNED_MAJOR}."):
        raise RuntimeError(
            f"OPA {version} found; this bundle is written for {PINNED_MAJOR}.x Rego"
        )

    port = port or _free_port()
    base_url = f"http://127.0.0.1:{port}"
    bundle_path = bundle.resolve()
    process = subprocess.Popen(  # noqa: S603 - see above
        [
            str(binary),
            "run",
            "--server",
            "--addr",
            f"127.0.0.1:{port}",
            "--set",
            "decision_logs.console=false",
            "--log-level",
            "error",
            bundle_path.name,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(bundle_path.parent),
    )
    try:
        _await_health(process, base_url)
        yield RunningSidecar(base_url, process)
    finally:
        RunningSidecar(base_url, process).stop()


def _await_health(process: subprocess.Popen[bytes], base_url: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if (code := process.poll()) is not None:
            stderr = (
                process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
            )
            raise RuntimeError(f"OPA exited with {code} before serving:\n{stderr}")
        try:
            with urlopen(f"{base_url}/health", timeout=1) as r:  # noqa: S310 - loopback
                if r.status == 200:
                    return
        except (URLError, OSError, TimeoutError):
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError(f"OPA did not become healthy at {base_url} within 30s")


def main() -> int:  # pragma: no cover - developer convenience
    with sidecar(port=8181) as url:
        print(f"OPA serving {BUNDLE} at {url} — Ctrl-C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
