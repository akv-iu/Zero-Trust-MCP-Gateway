"""Week-1 gate, run by hand: prove the fixture is genuinely unsafe.

    python -m scripts.damage_demo

This is `direct` mode — client straight to the fixture, no gateway. Every line of
output is a real filesystem operation on synthetic data. When the gateway exists,
`protected` mode must produce DENIED for every one of these, and the operation log
must show nothing.

Its value is as a baseline: you cannot claim the gateway prevented something unless
you first showed the something happens without it.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
BOLD, RED, GREEN, DIM, OFF = (
    ("\033[1m", "\033[31m", "\033[32m", "\033[2m", "\033[0m") if _TTY else ("",) * 5
)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="ztmg_demo_"))
    root, oplog = work / "fixture", work / "oplog.jsonl"
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(oplog)
    os.environ.pop("FIXTURE_MODE", None)

    from fixtures.build_tree import build, links_available, tree_hash
    from fixtures.filesystem_server import tools
    from fixtures.filesystem_server.oplog import read_ops
    from fixtures.manifest import CANARIES

    build(root)
    before = tree_hash(root)

    print(f"\n{BOLD}Zero-Trust MCP Gateway - direct-mode damage demo{OFF}")
    print(f"{DIM}fixture: {root}{OFF}")
    print(f"{DIM}oplog:   {oplog}{OFF}")
    print(f"{DIM}symlink traps available: {links_available(root)}{OFF}\n")
    print(f"{DIM}No gateway is involved. Everything below is what an unprotected")
    print(f"MCP client can do to the protected system today.{OFF}\n")

    demos: list[tuple[str, str, dict]] = [
        ("Read confidential salary data", "read_file",
         {"path": "confidential/fake_salaries.csv"}),
        ("Read a production secret", "read_file",
         {"path": "production/fake_config.env"}),
        ("Escape the public root by traversal", "read_file",
         {"path": "public/../confidential/fake_customer_list.csv"}),
        ("Read a decoy SSH private key", "read_file",
         {"path": "decoys/fake_ssh/id_rsa"}),
        ("Read decoy AWS credentials", "read_file",
         {"path": "decoys/fake_aws/credentials"}),
        ("Overwrite the production config", "write_file",
         {"path": "production/fake_config.env", "content": "OWNED_BY_DEMO\n"}),
        ("Delete confidential data", "delete_file",
         {"path": "confidential/fake_salaries.csv"}),
    ]

    breaches = 0
    for i, (label, tool, args) in enumerate(demos, 1):
        try:
            result = tools.call(tool, args)
            breaches += 1
            preview = str(result).replace("\n", " ")[:64]
            leaked = [c for c in CANARIES if c in str(result)]
            tag = f"  {RED}LEAKED {leaked[0]}{OFF}" if leaked else ""
            print(f"  {RED}[BREACH]{OFF} {i}. {label}")
            print(f"            {DIM}{tool}({args.get('path')}) -> {preview}{OFF}{tag}")
        except Exception as e:  # noqa: BLE001 - a demo failure is informative
            print(f"  {GREEN}[blocked]{OFF} {i}. {label} {DIM}({type(e).__name__}){OFF}")

    after = tree_hash(root)
    ops = [o for o in read_ops(oplog) if o["phase"] == "end"]

    print(f"\n{BOLD}Oracle{OFF}")
    print(f"  tree hash before : {before[:16]}...")
    print(f"  tree hash after  : {after[:16]}...  "
          f"{RED + 'CHANGED' + OFF if before != after else GREEN + 'unchanged' + OFF}")
    print(f"  operations logged: {len(ops)}  "
          f"({sum(1 for o in ops if o['outcome'] == 'ok')} succeeded)")

    print(f"\n{BOLD}Result{OFF}")
    print(f"  {RED}{breaches}/{len(demos)} unsafe operations succeeded against the "
          f"unprotected fixture.{OFF}")
    print(f"  {DIM}Week-1 gate needs >= 3. This is the baseline the gateway must "
          f"reduce to 0.{OFF}\n")

    shutil.rmtree(work, ignore_errors=True)
    return 0 if breaches >= 3 else 1


if __name__ == "__main__":
    sys.exit(main())
