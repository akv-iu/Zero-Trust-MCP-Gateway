"""Unit 05 acceptance tests — `_specs/05-svc-canonicalizer-fs.md` §9.

Every row of the spec's acceptance list is here, and so is its false-positive half:
spec test 15 says the legitimate cases get equal weight, because a canonicalizer that
denies everything scores perfectly on attacks and is worthless. The report publishes a
false-positive rate and this file is where it comes from.

The tests build a REAL fixture tree in `tmp_path` and resolve against it. A mock
filesystem would let the resolution logic be wrong in exactly the way that matters —
`..` and symlinks are filesystem behaviour, not string behaviour, and mocking them
means testing the mock.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fixtures.build_tree import build, links_available, tree_hash
from fixtures.manifest import CLASSIFICATION
from gateway import config as cfgmod
from gateway.canonicalize import fs
from gateway.config import CanonicalizeConfig, RootConfig
from gateway.errors import (
    CanonicalizationDenial,
    ConfigError,
    GatewayDenial,
    ReasonCode,
)
from gateway.types import CanonicalRequest, Operation, ResolvedTarget

REPO = Path(__file__).resolve().parents[2]

#: The tools the corpus uses, and the operation class the registry assigns each.
_OPERATIONS: dict[str, Operation] = {
    "read_file": "read",
    "list_directory": "read",
    "stat_file": "read",
    "write_file": "overwrite",
    "append_file": "append",
    "delete_file": "delete",
}


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    build(tmp_path / "fixture")
    return tmp_path / "fixture"


@pytest.fixture
def cfg(tree: Path) -> CanonicalizeConfig:
    """The shipped root layout, repointed at the test's tree.

    Read out of `config/gateway.toml` rather than written out here: a test that
    invents its own roots proves the code works and says nothing about whether the
    shipped file does, which is the lesson `test_shipped_config.py` exists for.
    """
    shipped = cfgmod.load(REPO / "config" / "gateway.toml").canonicalize
    return shipped.model_copy(
        update={
            "base": str(tree),
            "roots": tuple(
                r.model_copy(update={"path": str(tree / Path(r.path).name)})
                for r in shipped.roots
            ),
        }
    )


def request(
    path: str | None = "public/documentation.txt", **extra: Any
) -> CanonicalRequest:
    args: dict[str, Any] = dict(extra)
    if path is not None:
        args["path"] = path
    return CanonicalRequest(
        request_id="req-0",
        protocol_version="2026-07-28",
        method="tools/call",
        jsonrpc_id=1,
        tool_name="read_file",
        arguments=args,
        body_hash="body",
    )


def target(tool: str = "read_file") -> ResolvedTarget:
    return ResolvedTarget(
        server_id="filesystem-fixture",
        tool_name=tool,
        schema_fingerprint="v2:deadbeef",
        registry_risk_tier="R1",
        operation=_OPERATIONS[tool],
    )


def denied(path: str, cfg: CanonicalizeConfig, tool: str = "read_file") -> ReasonCode:
    """Canonicalize and return the reason code, failing if it was ALLOWED."""
    try:
        drv = fs.derive(request(path), target(tool), cfg)
    except CanonicalizationDenial as e:
        return e.reason_code
    pytest.fail(f"{path!r} was allowed: {drv.canonical_path} (root {drv.root})")


def allowed(path: str, cfg: CanonicalizeConfig, tool: str = "read_file") -> Any:
    return fs.derive(request(path), target(tool), cfg)


# ===========================================================================
# Spec tests 1-5, 10-13 — resolution
# ===========================================================================


def test_1_plain_traversal_escaping_every_root(cfg: CanonicalizeConfig) -> None:
    assert denied("public/../../../etc/passwd", cfg) is ReasonCode.CANON_OUTSIDE_ROOT


def test_2_encoded_traversal(cfg: CanonicalizeConfig) -> None:
    """`%2e%2e` decodes once to `..` and is then resolved, not matched as text."""
    assert (
        denied("public/%2e%2e/%2e%2e/%2e%2e/etc/passwd", cfg)
        is ReasonCode.CANON_OUTSIDE_ROOT
    )
    assert denied("%2e%2e%2f%2e%2e%2fetc", cfg) is ReasonCode.CANON_OUTSIDE_ROOT


def test_3_double_encoding_is_rejected_never_decoded_twice(
    cfg: CanonicalizeConfig,
) -> None:
    """CANON-001's whole point. `%252e` must not become `.` in two passes."""
    assert (
        denied("public/%252e%252e/confidential/fake_salaries.csv", cfg)
        is ReasonCode.CANON_ENCODING_INVALID
    )
    # And the rule is symmetric: one pass is applied, so a singly-encoded path
    # resolves rather than being rejected for containing a '%'.
    assert allowed("public/%64ocumentation.txt", cfg).root == "public"


def test_3b_malformed_encoding_is_rejected_not_repaired(
    cfg: CanonicalizeConfig,
) -> None:
    """`errors="strict"`. The default replaces bad bytes with U+FFFD, which is the
    silent repair CANON-002 forbids — the canonical path would name a file the client
    never asked for."""
    assert denied("public/%FF%FEdoc.txt", cfg) is ReasonCode.CANON_ENCODING_INVALID


@pytest.mark.parametrize("char", ["\x00", "\r", "\n", "\t", "\x7f", "\x1b"])
def test_4_control_characters_are_rejected(char: str, cfg: CanonicalizeConfig) -> None:
    assert denied(f"public/doc{char}ument.txt", cfg) is ReasonCode.CANON_NULL_BYTE


def test_4b_a_percent_encoded_null_byte_is_caught_after_decoding(
    cfg: CanonicalizeConfig,
) -> None:
    """The reason the control-character check runs TWICE. `%00` is invisible to the
    first pass and is the classic truncation attack in this class."""
    assert denied("public/documentation.txt%00.png", cfg) is ReasonCode.CANON_NULL_BYTE


@pytest.mark.parametrize(
    "path", ["/etc/passwd", "C:/Windows/System32/config/SAM", "//server/share/x"]
)
def test_5_absolute_path_escape(path: str, cfg: CanonicalizeConfig) -> None:
    """`Path("/root") / "/etc"` is `/etc` — the join REPLACES the root. Checked
    before the join, and under both path flavours: `PureWindowsPath` alone treats
    `/etc/passwd` as rootless and `PurePosixPath` alone treats `C:/x` as relative."""
    code = denied(path, cfg)
    assert code in (ReasonCode.CANON_OUTSIDE_ROOT, ReasonCode.CANON_PATH_REJECTED)


def test_10_separator_variants_produce_the_same_canonical_result(
    cfg: CanonicalizeConfig,
) -> None:
    """CANON-006. `\\` is translated on every platform, not only on Windows: a corpus
    row that means one thing on WSL2 and another in CI measures nothing."""
    forward = allowed("public/documentation.txt", cfg)
    back = allowed("public\\documentation.txt", cfg)
    assert forward.canonical_path == back.canonical_path
    assert forward.root == back.root


def test_11_sibling_prefix_collision_is_not_containment(tmp_path: Path) -> None:
    """CANON-008, and the one substitution that would silently disable this module.

    A root of `.../pub` must not contain `.../public-secrets`. `is_relative_to`
    compares path components and gets this right; `str.startswith` does not, and
    swapping them is the most common path-traversal bug in production gateways.
    Break-verified: replacing the comparison in `_containing_root` with `startswith`
    makes this test fail and nothing else in the file notice.
    """
    (tmp_path / "pub").mkdir()
    (tmp_path / "pub" / "ok.txt").write_text("fine", encoding="utf-8")
    (tmp_path / "public-secrets").mkdir()
    (tmp_path / "public-secrets" / "leak.txt").write_text("no", encoding="utf-8")

    narrow = CanonicalizeConfig(
        base=str(tmp_path),
        roots=(
            RootConfig(
                name="pub", path=str(tmp_path / "pub"), classification="public", read=True
            ),
        ),
    )
    assert allowed("pub/ok.txt", narrow).root == "pub"
    assert denied("public-secrets/leak.txt", narrow) is ReasonCode.CANON_OUTSIDE_ROOT


def test_12_unicode_variants_resolve_against_the_filesystem(tree: Path) -> None:
    """Spec test 12. NFC normalization happens before resolution, so the two spellings
    of the same character reach the filesystem as one.

    The assertion is deliberately about EQUALITY of outcome rather than about success:
    on a filesystem that stores NFD (macOS) the resolved bytes differ from the input,
    which is exactly why `_tech/05` §10 says to compare resolved-to-resolved and never
    resolved-to-input.
    """
    (tree / "public" / "caf\u00e9.txt").write_text("nfc", encoding="utf-8")
    cfg = CanonicalizeConfig(
        base=str(tree),
        roots=(
            RootConfig(
                name="public",
                path=str(tree / "public"),
                classification="public",
                read=True,
            ),
        ),
    )
    nfc = allowed("public/caf\u00e9.txt", cfg)
    nfd = allowed("public/cafe\u0301.txt", cfg)
    assert nfc.canonical_path == nfd.canonical_path
    assert nfc.arg_hash != nfd.arg_hash, (
        "arg_hash covers the ARGUMENTS as sent as well as the canonical path; two "
        "spellings are two different requests even when they name one file"
    )


@pytest.mark.parametrize(
    "variant",
    [
        "public/documentation.txt",
        "public//documentation.txt",
        "public/./documentation.txt",
        "./public/documentation.txt",
        "public/../public/documentation.txt",
        "workspace/../public/documentation.txt",
    ],
)
def test_13_equivalent_spellings_share_one_canonical_path(
    variant: str, cfg: CanonicalizeConfig
) -> None:
    """Spec test 13. One resource identity per file, whatever the client typed —
    without it, policy could allow a path it has already denied."""
    assert (
        allowed(variant, cfg).canonical_path
        == allowed("public/documentation.txt", cfg).canonical_path
    )


def test_a_trailing_separator_does_not_change_the_target(cfg: CanonicalizeConfig) -> None:
    listing = fs.derive(request("public/"), target("list_directory"), cfg)
    assert (
        listing.canonical_path == allowed("public", cfg, "list_directory").canonical_path
    )


# ===========================================================================
# Spec tests 6-8 — symlinks. SKIPPED, never passed, where the platform refuses.
# ===========================================================================
#
# FIX-003: a skip is reported as a skip and never counted as a pass. Windows needs
# Developer Mode or an elevated shell to create a symlink, so on this developer's
# machine these three report SKIPPED and the benchmark says so.

symlinks = pytest.mark.skipif(
    not hasattr(os, "symlink"), reason="platform has no symlink support"
)


@symlinks
def test_6_symlink_escaping_the_tree(tree: Path, cfg: CanonicalizeConfig) -> None:
    """`traps/escape_link -> ../..` leaves the fixture entirely."""
    if not links_available(tree):
        pytest.skip("symlink creation refused by the platform (FIX-003)")
    assert denied("traps/escape_link/etc/passwd", cfg) is ReasonCode.CANON_SYMLINK_ESCAPE


@symlinks
def test_7_symlink_escape_via_an_intermediate_component(
    tree: Path, cfg: CanonicalizeConfig
) -> None:
    """CANON-004: EVERY component is resolved, not only the last one.

    `resolve` gives this for free — which is the reason `_tech/05` §10 forbids a
    hand-rolled component walk, where it is exactly the case that gets missed.
    """
    if not links_available(tree):
        pytest.skip("symlink creation refused by the platform (FIX-003)")
    (tree / "public" / "sub").mkdir(exist_ok=True)
    try:
        (tree / "public" / "sub" / "out").symlink_to(tree.parent)
    except OSError:
        pytest.skip("symlink creation refused by the platform (FIX-003)")
    assert (
        denied("public/sub/out/fixture/confidential/fake_salaries.csv", cfg)
        is ReasonCode.CANON_SYMLINK_ESCAPE
    )


@symlinks
def test_8_symlink_loop_is_a_denial_not_a_fallback(
    tree: Path, cfg: CanonicalizeConfig
) -> None:
    """CANON-009. Resolution failure never falls back to the unresolved string —
    that fallback is how a traversal ends up authorised on its raw text."""
    if not links_available(tree):
        pytest.skip("symlink creation refused by the platform (FIX-003)")
    assert denied("traps/loop_a", cfg) is ReasonCode.CANON_RESOLUTION_FAILED


@symlinks
def test_a_link_that_stays_inside_a_root_is_allowed(
    tree: Path, cfg: CanonicalizeConfig
) -> None:
    """The false-positive control for tests 6-8: `traps/public_link -> ../public` is
    legitimate, and a canonicalizer that denied every symlink would look identical to
    a correct one on the attack rows alone."""
    if not links_available(tree):
        pytest.skip("symlink creation refused by the platform (FIX-003)")
    drv = allowed("traps/public_link/documentation.txt", cfg)
    assert drv.root == "public", "resolution follows the link into the root it lands in"


def test_resolution_failure_when_the_target_does_not_exist(
    cfg: CanonicalizeConfig,
) -> None:
    """CANON-009 without needing symlinks, so it runs on every platform."""
    assert denied("public/absent.txt", cfg) is ReasonCode.CANON_RESOLUTION_FAILED


# ===========================================================================
# Spec test 9 — case, on the target filesystem's ACTUAL semantics
# ===========================================================================


def _folds_case(root: Path) -> bool:
    probe = root / ".case_probe_XYZ"
    probe.write_text("", encoding="utf-8")
    try:
        return (root / ".case_probe_xyz").exists()
    finally:
        probe.unlink()


def test_9_case_variants_follow_the_filesystem_not_an_assumption(
    tree: Path, cfg: CanonicalizeConfig
) -> None:
    """CANON-005, and the reason there is no case-sensitivity probe in production code.

    Containment compares a RESOLVED path to a RESOLVED root, and `realpath` returns
    the true on-disk spelling of every component that exists. So on a case-folding
    filesystem `PUBLIC/DOCUMENTATION.TXT` canonicalizes to the identical string as
    the correctly-spelled path — distinct-case paths are treated as identical for
    containment without any casefolding logic — and on a case-sensitive one it names
    nothing and is denied. Both are safe; neither is an assumption about the platform.
    """
    if _folds_case(tree):
        variant = allowed("PUBLIC/DOCUMENTATION.TXT", cfg)
        assert (
            variant.canonical_path
            == allowed("public/documentation.txt", cfg).canonical_path
        )
        assert variant.root == "public", (
            "case folding must not let a path evade the root it really lives in"
        )
    else:
        assert (
            denied("PUBLIC/DOCUMENTATION.TXT", cfg) is ReasonCode.CANON_RESOLUTION_FAILED
        )


# ===========================================================================
# CANON-016 — path syntaxes refused outright
# ===========================================================================


@pytest.mark.parametrize(
    "path",
    [
        "public/CON",
        "public/con.txt",
        "public/LPT1.log",
        "public/nul",
        "public/documentation.txt:hidden",
        "public/documentation.txt.",
        "public/documentation.txt ",
        "public/sub./x",
    ],
)
def test_hostile_path_syntax_is_refused(path: str, cfg: CanonicalizeConfig) -> None:
    """Reserved device names, alternate data streams, and Win32's silent stripping of
    a trailing dot or space. Applied on POSIX too — see the module docstring."""
    assert denied(path, cfg) is ReasonCode.CANON_PATH_REJECTED


def test_an_over_long_path_is_refused_before_the_filesystem_is_touched(
    cfg: CanonicalizeConfig,
) -> None:
    assert (
        denied("public/" + "a" * cfg.max_path_length, cfg)
        is ReasonCode.CANON_PATH_REJECTED
    )


# ===========================================================================
# Spec test 14 — sensitive locations
# ===========================================================================


@pytest.mark.parametrize(
    "decoy",
    [
        "decoys/fake_ssh/id_rsa",
        "decoys/fake_aws/credentials",
        "decoys/fake_env/.env",
    ],
)
@pytest.mark.parametrize("tool", ["read_file", "stat_file", "delete_file"])
def test_14_every_decoy_is_denied_for_every_tool(
    decoy: str, tool: str, cfg: CanonicalizeConfig
) -> None:
    """CANON-014. Stage 05 denies before policy, so no principal and no policy edit
    can reach one — there is no rule to get wrong."""
    assert denied(decoy, cfg, tool) is ReasonCode.CANON_SENSITIVE_PATH


def test_14b_a_decoy_reached_by_traversal_is_still_a_decoy(
    cfg: CanonicalizeConfig,
) -> None:
    """The check is on the RESOLVED path, so spelling does not evade it."""
    assert (
        denied("public/../decoys/fake_ssh/id_rsa", cfg) is ReasonCode.CANON_SENSITIVE_PATH
    )


def test_14c_the_decoy_list_covers_a_listed_directorys_contents(tmp_path: Path) -> None:
    """A directory on the list takes its whole subtree with it. Listing every file
    under `~/.ssh` individually is how one gets missed."""
    (tmp_path / "keys" / "inner").mkdir(parents=True)
    (tmp_path / "keys" / "inner" / "id_ed25519").write_text("k", encoding="utf-8")
    cfg = CanonicalizeConfig(
        base=str(tmp_path),
        roots=(
            RootConfig(
                name="keys",
                path=str(tmp_path / "keys"),
                classification="secret",
                read=True,
            ),
        ),
        sensitive_decoys=("keys",),
    )
    assert denied("keys/inner/id_ed25519", cfg) is ReasonCode.CANON_SENSITIVE_PATH


# ===========================================================================
# Spec test 15 — the false-positive side, weighted equally
# ===========================================================================


@pytest.mark.parametrize(
    ("tool", "path", "expected_root", "expected_operation"),
    [
        ("read_file", "public/documentation.txt", "public", "read"),
        ("read_file", "public/changelog.md", "public", "read"),
        ("read_file", "workspace/notes.txt", "workspace", "read"),
        ("stat_file", "workspace/notes.txt", "workspace", "read"),
        ("list_directory", "workspace/scratch", "workspace", "read"),
        ("write_file", "workspace/notes.txt", "workspace", "overwrite"),
        ("write_file", "workspace/scratch/new.txt", "workspace", "create"),
        ("append_file", "workspace/notes.txt", "workspace", "append"),
        ("delete_file", "workspace/notes.txt", "workspace", "delete"),
    ],
)
def test_15_legitimate_work_canonicalizes(
    tool: str,
    path: str,
    expected_root: str,
    expected_operation: str,
    cfg: CanonicalizeConfig,
) -> None:
    drv = fs.derive(request(path), target(tool), cfg)
    assert drv.root == expected_root
    assert drv.operation == expected_operation
    assert drv.canonical_path.endswith(path.rsplit("/", 1)[-1])


def test_15b_classification_comes_from_layout_not_content(
    cfg: CanonicalizeConfig,
) -> None:
    """CANON-013. Every top-level directory of the fixture maps to the classification
    `fixtures/manifest.py` records, and the mapping is the ROOT's, never the file's."""
    for directory, classification in CLASSIFICATION.items():
        root = next(r for r in cfg.roots if r.name == directory)
        assert root.classification == classification, (
            f"config/gateway.toml classifies {directory!r} as "
            f"{root.classification!r}; fixtures/manifest.py says {classification!r}"
        )
    assert allowed("public/documentation.txt", cfg).classification == "public"
    assert allowed("workspace/notes.txt", cfg).classification == "internal"


def test_15c_confidential_and_production_reach_policy_rather_than_being_unnameable(
    cfg: CanonicalizeConfig,
) -> None:
    """The reason those directories are roots with every flag false.

    Canonicalization SUCCEEDS and hands policy `classification: confidential`. Leaving
    them out of the roots instead would deny them at stage 05 with the same code as a
    path pointing at nothing at all, and the audit log could no longer tell "someone
    tried to read salary data" from "someone typo'd a directory name".
    """
    for path, classification in (
        ("confidential/fake_salaries.csv", "confidential"),
        ("production/fake_config.env", "production"),
    ):
        drv = allowed(path, cfg)
        assert drv.classification == classification
        assert drv.operation == "read"


# ===========================================================================
# Spec test 16 — the oracle confirms nothing happened
# ===========================================================================


def test_16_no_denial_touches_the_protected_system(
    tree: Path, cfg: CanonicalizeConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HARN-005: proven by observing the fixture, not by reading the denial.

    Weaker than the corpus's oracle by design — `derive` is a pure function and has
    no route to the fixture at all — but it is the assertion that would fail if this
    module ever grew one, for instance by "checking" a path with an open() call.
    """
    from fixtures.filesystem_server.oplog import read_ops

    oplog = tree.parent / "oplog.jsonl"
    monkeypatch.setenv("FIXTURE_OPLOG", str(oplog))
    before = tree_hash(tree)

    attacks = [
        "public/../../../etc/passwd",
        "public/%2e%2e/%2e%2e/etc/passwd",
        "public/%252e%252e/x",
        "/etc/passwd",
        "public/doc\x00ument.txt",
        "decoys/fake_ssh/id_rsa",
        "public/CON",
        "public/absent.txt",
    ]
    for path in attacks:
        assert denied(path, cfg, "read_file")

    assert tree_hash(tree) == before, "canonicalization modified the protected tree"
    assert not read_ops(oplog), "canonicalization performed a fixture operation"


# ===========================================================================
# Spec test 17 — the startup self-check
# ===========================================================================


def _shipped_config_rooted_at(tmp_path: Path) -> Any:
    """The shipped `Config` with its base and roots pointed at `tmp_path/fixture`.

    Repointing the model beats rewriting the TOML: `self_check` reads the model, and
    three chained `str.replace` calls over a config file is a second parser nobody
    asked for.
    """
    cfg = cfgmod.load(REPO / "config" / "gateway.toml")
    canon = cfg.canonicalize
    return cfg.model_copy(
        update={
            "canonicalize": canon.model_copy(
                update={
                    "base": str(tmp_path / "fixture"),
                    "roots": tuple(
                        r.model_copy(
                            update={"path": str(tmp_path / "fixture" / Path(r.path).name)}
                        )
                        for r in canon.roots
                    ),
                }
            )
        }
    )


@pytest.mark.parametrize("owned", ["registry_path", "audit"])
def test_17_startup_fails_when_a_root_would_contain_a_gateway_owned_path(
    owned: str, tmp_path: Path
) -> None:
    """CANON-015. The gateway's own configuration, registry and audit output must lie
    outside every approved root, or a `read_file` is a way to read the policy that
    permitted it — and a `write_file` is a way to edit it."""
    leaked = str(tmp_path / "fixture" / "workspace" / "leaked")
    cfg = _shipped_config_rooted_at(tmp_path)
    if owned == "registry_path":
        cfg = cfg.model_copy(update={"registry_path": leaked})
    else:
        cfg = cfg.model_copy(
            update={"audit": cfg.audit.model_copy(update={"path": leaked})}
        )
    with pytest.raises(ConfigError, match="lies inside approved root"):
        cfg.self_check()


def test_17b_the_config_file_itself_is_checked(tmp_path: Path) -> None:
    """`Config` does not know where it came from, so `self_check` takes the path.

    Without the argument the first item CANON-015 names — "the gateway's own
    configuration" — was the one thing the check could not see.
    """
    cfg = _shipped_config_rooted_at(tmp_path)
    inside = tmp_path / "fixture" / "workspace" / "gateway.toml"

    cfg.self_check()  # without the path, invisible
    with pytest.raises(ConfigError, match="lies inside approved root"):
        cfg.self_check(inside)


# ===========================================================================
# Spec test 18 — Hypothesis
# ===========================================================================

_SEGMENTS = [
    "..",
    ".",
    "%2e%2e",
    "%252e",
    "%2f",
    "\\",
    "/",
    "\x00",
    "public",
    "workspace",
    "confidential",
    "decoys",
    "traps",
    "escape_link",
    "documentation.txt",
    "CON",
    "x.",
    "id_rsa",
]


@settings(max_examples=400, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(parts=st.lists(st.sampled_from(_SEGMENTS), min_size=1, max_size=6))
def test_18_a_generated_path_either_denies_or_lands_inside_a_root(
    parts: list[str], cfg: CanonicalizeConfig
) -> None:
    """The invariant, and the only one that matters: never *outside a root and allowed*.

    Composed from an adversarial alphabet rather than from arbitrary text, because
    the interesting inputs are the ones that look like traversal — random unicode
    would spend its whole budget on paths that do not exist.
    """
    path = "/".join(parts)
    try:
        drv = fs.derive(request(path), target("read_file"), cfg)
    except CanonicalizationDenial:
        return
    real = Path(drv.canonical_path)
    root = next(r for r in cfg.roots if r.name == drv.root)
    assert real.is_relative_to(Path(os.path.realpath(root.path))), (
        f"{path!r} was ALLOWED and resolved to {real}, which is outside root "
        f"{drv.root} — the one outcome this module exists to prevent"
    )
    assert real.exists(), "an allowed read names a file that is not there"


# ===========================================================================
# Derived attributes, hashes, and the tool-less target
# ===========================================================================


def test_the_raw_path_never_reaches_policy_input(cfg: CanonicalizeConfig) -> None:
    """CANON-010. `DerivedAttributes` is what unit 06 evaluates, and the client's own
    string is present only as a hash (CONV-012)."""
    drv = allowed("public/../public/documentation.txt", cfg)
    dumped = json.dumps(drv.model_dump())
    assert "public/../public" not in dumped
    assert drv.raw_hash != drv.arg_hash


def test_11_arg_hash_covers_the_canonical_path_so_unit_07_can_compare(
    cfg: CanonicalizeConfig,
) -> None:
    """CANON-011 / ROUTE-002. Two spellings of one file share a canonical path but
    not an `arg_hash`, and two different files never share either."""
    a = allowed("public/documentation.txt", cfg)
    b = allowed("public/changelog.md", cfg)
    assert a.arg_hash != b.arg_hash
    assert a.raw_hash != b.raw_hash
    again = allowed("public/documentation.txt", cfg)
    assert a.arg_hash == again.arg_hash, "the hash must be stable across requests"


def test_create_and_overwrite_are_distinguished_by_existence(
    tree: Path, cfg: CanonicalizeConfig
) -> None:
    """CANON-012. Collapsing them into "write" loses the distinction that makes the
    fixture demo meaningful — policy expresses different rules for each."""
    fresh = fs.derive(request("workspace/brand_new.txt"), target("write_file"), cfg)
    assert fresh.operation == "create" and fresh.exists is False

    (tree / "workspace" / "brand_new.txt").write_text("now it is here", encoding="utf-8")
    again = fs.derive(request("workspace/brand_new.txt"), target("write_file"), cfg)
    assert again.operation == "overwrite" and again.exists is True


def test_a_create_into_a_nonexistent_directory_is_refused(
    cfg: CanonicalizeConfig,
) -> None:
    """The parent must resolve even when the leaf may not. Resolving the whole path
    loosely and allowing it would let a symlinked parent escape undetected."""
    assert (
        denied("workspace/no/such/dir/f.txt", cfg, "write_file")
        is ReasonCode.CANON_RESOLUTION_FAILED
    )


def test_a_create_outside_every_root_is_refused(cfg: CanonicalizeConfig) -> None:
    """Containment applies to a path that does not exist yet, which is the case a
    read-only test sweep would never cover."""
    assert (
        denied("workspace/../../escaped.txt", cfg, "write_file")
        is ReasonCode.CANON_OUTSIDE_ROOT
    )


def test_tools_list_gets_a_resource_free_derivation(cfg: CanonicalizeConfig) -> None:
    """Unit 04 returns a tool-less R0 target for `tools/list`; this is stage 05's
    half of the debt `PLAN.md` §4.2 recorded against this unit."""
    listing = CanonicalRequest(
        request_id="req-list",
        protocol_version="2026-07-28",
        method="tools/list",
        jsonrpc_id=1,
        tool_name=None,
        arguments={},
        body_hash="body",
    )
    tgt = ResolvedTarget(
        server_id="filesystem-fixture",
        tool_name=None,
        schema_fingerprint=None,
        registry_risk_tier="R0",
        operation="read",
    )
    drv = fs.derive(listing, tgt, cfg)
    assert drv.canonical_path == "" and drv.root == "" and drv.classification == ""
    assert drv.exists is False
    assert not any(r.name == "" for r in cfg.roots), (
        "the empty root name is the sentinel; a real root may never use it"
    )


def test_a_root_may_not_be_nameless() -> None:
    """What makes the sentinel above unambiguous, asserted rather than assumed."""
    with pytest.raises(ValueError, match="non-empty name"):
        RootConfig(name="", path="/tmp", classification="public")
    with pytest.raises(ValueError, match="non-empty name"):
        RootConfig(name="x", path="/tmp", classification="")


def test_a_missing_path_argument_uses_the_upstreams_own_default(
    cfg: CanonicalizeConfig,
) -> None:
    """`list_directory` defaults `path` to "." at the fixture, so the gateway must
    canonicalize the same target — the base, which is inside no root and is therefore
    denied. A different default here would authorize a directory the upstream would
    never open, or refuse one it would."""
    bare = CanonicalRequest(
        request_id="req-bare",
        protocol_version="2026-07-28",
        method="tools/call",
        jsonrpc_id=1,
        tool_name="list_directory",
        arguments={},
        body_hash="body",
    )
    with pytest.raises(CanonicalizationDenial) as exc:
        fs.derive(bare, target("list_directory"), cfg)
    assert exc.value.reason_code is ReasonCode.CANON_OUTSIDE_ROOT


# ===========================================================================
# Configuration and wiring
# ===========================================================================


#: What `decode_rule_version = "v1"` MEANS, as behaviour rather than as a string.
#: `None` is a rejection. Extend on a bump; never edit an existing row in place.
DECODE_GOLDEN: dict[str, dict[str, str | None]] = {
    "v1": {
        "plain.txt": "plain.txt",
        "a%2fb": "a/b",
        "%2e%2e": "..",
        "caf%C3%A9.txt": "café.txt",
        "100%25": "100%",
        "%252e%252e": None,  # residual encoding after one pass
        "%2": "%2",  # NOT rejected: the rule names `%` + two hex digits, and this is
        # not that. It survives as a literal and then names no file. Pinned because
        # the tempting "reject anything containing %" is a different rule.
        "a+b": "a+b",  # `+` is NOT a space. `unquote_plus` would decode it, and the
        # rule says no other decoding is applied. Added when the break pass swapped
        # `unquote` for `unquote_plus` and every other vector stayed green.
        "%FF%FE": None,  # malformed UTF-8, never replaced with U+FFFD
        "a%00b": "a\x00b",  # decoded here; the control-character step is what rejects it
    }
}


def test_the_decode_rule_version_tracks_the_rule() -> None:
    """CANON-001, enforced the way `FINGERPRINT_VERSION` had to be enforced.

    The first attempt compared `cfg.decode_rule_version` to the module constant at
    startup. That was theatre twice over: the config field is a single-member
    `Literal`, so pydantic refuses any other value before the check runs, and the
    comparison was blind to the failure that actually occurs — someone edits
    `decode_once` and leaves the version string alone, at which point both sides
    still agree. `hashing.FINGERPRINT_VERSION` was bitten by exactly that, and what
    caught it there was a golden value per version.

    So: a table of inputs to outcomes, keyed on the version. Change what `decode_once`
    does without bumping `IMPLEMENTED_DECODE_RULE` and there is no row to move the
    behaviour to, and this fails.
    """
    rule = fs.IMPLEMENTED_DECODE_RULE
    assert rule in DECODE_GOLDEN, (
        f"decode rule {rule!r} has no golden vectors — bumping the version means "
        "adding the table that says what the new rule does"
    )
    for raw, expected in DECODE_GOLDEN[rule].items():
        if expected is None:
            with pytest.raises(CanonicalizationDenial) as exc:
                fs.decode_once(raw)
            assert exc.value.reason_code is ReasonCode.CANON_ENCODING_INVALID
        else:
            assert fs.decode_once(raw) == expected, raw


def test_the_shipped_config_names_the_rule_this_build_implements() -> None:
    """The `Literal` is the enforcement; this is the assertion that it is set to it."""
    cfg = cfgmod.load(REPO / "config" / "gateway.toml").canonicalize
    assert cfg.decode_rule_version == fs.IMPLEMENTED_DECODE_RULE


def test_nested_roots_resolve_to_the_most_specific_one(tmp_path: Path) -> None:
    """Order in the file must not decide which root a path belongs to — the
    classification and the permissions ride on the answer."""
    (tmp_path / "ws" / "scratch").mkdir(parents=True)
    (tmp_path / "ws" / "scratch" / "f.txt").write_text("x", encoding="utf-8")
    cfg = CanonicalizeConfig(
        base=str(tmp_path),
        roots=(
            RootConfig(
                name="ws", path=str(tmp_path / "ws"), classification="internal", read=True
            ),
            RootConfig(
                name="scratch",
                path=str(tmp_path / "ws" / "scratch"),
                classification="ephemeral",
                read=True,
            ),
        ),
    )
    assert allowed("ws/scratch/f.txt", cfg).root == "scratch"


def test_stage_05_contributes_only_fields_the_audit_schema_defines(
    cfg: CanonicalizeConfig,
) -> None:
    from gateway.audit_schema import RequestEvent

    fields = fs.audit_fields(allowed("public/documentation.txt", cfg))
    assert set(fields) <= set(RequestEvent.model_fields)
    assert fields["classification"] == "public"
    assert fields["operation"] == "read"


def test_no_raw_path_is_audited(cfg: CanonicalizeConfig) -> None:
    """AUDIT-005 / CONV-012 from the stage that actually holds the path."""
    fields = fs.audit_fields(allowed("public/../public/documentation.txt", cfg))
    assert "public/../public" not in json.dumps(fields)


async def test_the_pipeline_actually_persists_the_stage_05_fields(
    tmp_path: Path, audit_events: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wiring, not the function — the shape this project has caught four times.

    Every assertion above calls `fs.audit_fields()` itself, so deleting
    `builder.set(**canonicalize.audit_fields(drv))` from `pipeline.handle` would leave
    them all green while every real record went out with no `canonical_resource`, no
    `classification` and no `arg_hash`. Break-verified by removing that line and
    confirming this test — and only this test — fails.
    """
    from gateway.audit import AuditSink
    from gateway.pipeline import Deps, handle
    from gateway.registry import Registry
    from harness.scenario import Scenario
    from harness.wire import build_envelope

    build(tmp_path / "fixture")
    shipped = cfgmod.load(REPO / "config" / "gateway.toml")
    canon = shipped.canonicalize
    cfg = shipped.model_copy(
        update={
            "canonicalize": canon.model_copy(
                update={
                    "base": str(tmp_path / "fixture"),
                    "roots": tuple(
                        r.model_copy(
                            update={"path": str(tmp_path / "fixture" / Path(r.path).name)}
                        )
                        for r in canon.roots
                    ),
                }
            )
        }
    )

    reg = Registry.load(REPO / "config" / "registry.toml")
    reg.verify_schemas(
        [
            {
                "name": t.name,
                "description": None,
                "inputSchema": t.approved_schema,
            }
            for t in reg.server.tool
        ]
    )
    # Fingerprints will not match these synthesised descriptions, which is fine: the
    # tool under test only needs the registry SEALED so stage 04 resolves.
    reg._drift.clear()  # noqa: SLF001 - sealing without a live child

    sink = AuditSink(tmp_path / "audit.jsonl")
    sink.open()
    deps = Deps(config=cfg, registry=reg, opa=None, upstream=None, audit=sink)

    scenario = Scenario.model_validate(
        {
            "id": "canonicalize-wiring-probe",
            "class": "legitimate",
            "layer": "protocol",
            "principal": "developer",
            "tool": "read_file",
            "arguments": {"path": "public/documentation.txt"},
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {"op": "read", "path_contains": "public"},
            "risk_tier": "R1",
            "notes": "Drives the real pipeline far enough to prove stage 05 is wired.",
        }
    )

    before = len(audit_events)
    # Stage 06 is still a stub, so the request dies there — the `finally` writes the
    # event regardless, so anything stage 05 set is already on it.
    with pytest.raises(GatewayDenial):
        await handle(build_envelope(scenario), deps)
    (event,) = audit_events[before:]

    assert "canonical" in event.stage_latency_ms, "stage 05 did not run"
    assert event.canonical_resource is not None
    assert event.canonical_resource.endswith("public/documentation.txt")
    assert event.classification == "public"
    assert event.operation == "read"
    assert event.arg_hash and event.raw_hash

    persisted = json.loads(sink.path.read_text("utf-8").splitlines()[-1])
    assert persisted["classification"] == "public"
    assert persisted["arg_hash"] == event.arg_hash
    sink.close()


@pytest.mark.parametrize(
    "client_path",
    [
        "public/documentation.txt",
        "%70ublic/documentation.txt",
        "public/./documentation.txt",
        "workspace/notes.txt",
    ],
)
def test_the_two_paths_this_unit_emits_describe_one_resource(
    client_path: str, cfg: CanonicalizeConfig
) -> None:
    """`canonical_path` and `relative_path` MUST name the same file. Unit 07 assumes it.

    Stage 06 authorizes against `canonical_path`; stage 07 forwards `relative_path` and
    the child rejoins it onto its own base. Nothing at runtime ties the two together, so
    if this unit ever derived them separately the gateway would authorize resource A and
    cause a side effect on resource B — with an audit record naming A. That is the worst
    failure either unit can have and it is completely silent.

    Codex raised it against unit 07, where it cannot be tested: the router receives
    `DerivedAttributes` and has no filesystem access to check them (ROUTE-003). Feeding
    it a deliberately inconsistent pair proves nothing about production, and feeding it
    a consistent one proves nothing either. The invariant belongs where the pair is
    MADE, which is here.
    """
    drv = allowed(client_path, cfg)

    assert drv.relative_path, f"{client_path}: no relative path derived"
    rejoined = (Path(cfg.base) / drv.relative_path).resolve()
    assert rejoined == Path(drv.canonical_path).resolve(), (
        f"{client_path}: authorized {drv.canonical_path!r} but would forward "
        f"{drv.relative_path!r}, which the upstream resolves to {rejoined!r}"
    )


pytestmark = pytest.mark.anyio
