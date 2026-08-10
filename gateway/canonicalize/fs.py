"""05 - Filesystem path canonicalization and derived policy attributes.

Spec: _specs/05-svc-canonicalizer-fs.md   Tech: _tech/05-svc-canonicalizer-fs.md

STATED LIMITATION, first because it is the thing most likely to be overclaimed:
the primary filesystem control is the sandbox mount (unit 10), not this module.
Canonicalizing a path and then handing a *string* to a separate process is racy by
construction — the filesystem can change between resolution and use, and unit 07
forwards the argument the client sent, not the path resolved here. That TOCTOU
window cannot be closed at the gateway. This unit is defense in depth and a
policy-input requirement: it is what lets policy reason about a stable resource
identity. It does **not** claim TOCTOU safety.

THE ORDER, and every step may only reject or narrow:

    1  length gate                                     CANON_PATH_REJECTED
    2  control characters, as supplied                 CANON_NULL_BYTE
    3  percent-decode exactly once                     CANON_ENCODING_INVALID
    4  residual percent-encoding                       CANON_ENCODING_INVALID
    5  control characters, after decoding              CANON_NULL_BYTE
    6  NFC, then `\\` -> `/`
    7  hostile component syntax                        CANON_PATH_REJECTED
    8  absolute / drive / UNC                          CANON_OUTSIDE_ROOT
    9  resolve against the real filesystem
    10 containment, segment-aware        CANON_OUTSIDE_ROOT / CANON_SYMLINK_ESCAPE
    11 sensitive decoys                                CANON_SENSITIVE_PATH
    12 existence, per operation class                  CANON_RESOLUTION_FAILED
    13 derive attributes

CONTAINMENT BEFORE EXISTENCE, which is a deliberate departure from `_tech/05` §3.
The tech sheet resolves with ``strict=True`` first, so a read of a path outside every
root reports CANON_RESOLUTION_FAILED when the target happens not to exist and
CANON_OUTSIDE_ROOT when it does. Two problems, and the second is decisive:

  * the reason code becomes an existence oracle across the security boundary — a
    probe learns whether `../../../etc/shadow` is there from the code it gets back;
  * the corpus is a published artifact that must score identically on WSL2 and on
    Windows, and `/etc/passwd` exists on exactly one of them.

Resolving as far as the filesystem allows, checking the boundary, and only then
requiring existence gives one code per cause on every platform. It gives up nothing:
a symlink anywhere in the existing prefix is still resolved, and the components that
remain unresolved are by definition the ones that do not exist, so they cannot be
symlinks and cannot move the path anywhere.

PLATFORM RULES ARE UNCONDITIONAL. Reserved device names, alternate data streams,
trailing dots and spaces, and `\\` as a separator are Windows concerns, and this
module applies them on POSIX too. A corpus row that means one thing on the developer's
machine and another in CI does not measure anything, and every one of these rules can
only ever deny more. `\\` is *translated*, not rejected, because CANON-006 requires a
separator variant to produce the same canonical result as its equivalent; on POSIX
that costs the ability to name a file with a literal backslash in it, which the
fixture does not contain and which the report records as an accepted false positive.

NO CASE-SENSITIVITY PROBE. `_tech/05` §5 proposes touching a file at startup to learn
whether the filesystem folds case. It is not needed, and CANON-005 is satisfied more
directly without it: containment compares a resolved path to a resolved root, and
`realpath` returns the true on-disk spelling of every component that exists — on
Windows `public/doc.txt` and `PUBLIC/DOC.TXT` both come back as the one form the
directory actually uses. That is "the actual semantics of the target filesystem"
rather than an assumption about it. Components that do NOT exist keep the supplied
case, which is harmless: a name that is not on disk cannot collide with one that is.
"""

from __future__ import annotations

import os
import re
import unicodedata
import urllib.parse
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final, NamedTuple

from gateway import hashing
from gateway.config import CanonicalizeConfig, RootConfig
from gateway.errors import CanonicalizationDenial, ReasonCode
from gateway.types import (
    CanonicalRequest,
    DerivedAttributes,
    JsonObject,
    Operation,
    ResolvedTarget,
)

IMPLEMENTED_DECODE_RULE: Final = "v1"
"""The rule `decode_once` implements. `config.CanonicalizeConfig.decode_rule_version`
is the `Literal` that must equal it.

v1: *A supplied path is percent-decoded exactly once using UTF-8. After that single
pass, any remaining `%` followed by two hex digits causes rejection. No other decoding
is applied — no unicode-escape, no HTML entity, no backslash escape.*

Reproduced verbatim in `docs/threat-model.md`.

The enforcement is a GOLDEN VECTOR SET per version, not a startup comparison of this
string against the config's. That was the first attempt and it was theatre: the config
field is a single-member `Literal`, so pydantic already refuses any other value, and
the comparison was blind to the failure that actually happens — someone edits
`decode_once` and leaves this string alone, at which point both sides still agree and
the check passes. `hashing.FINGERPRINT_VERSION` learned this the expensive way, twice.
`test_canonicalize.py::test_the_decode_rule_version_tracks_the_rule` pins what v1 does
to a table of inputs, so changing the behaviour without changing the version fails.
"""

_PERCENT_HEX: Final = re.compile(r"%[0-9A-Fa-f]{2}")

_PATH_ARG: Final = "path"
"""The argument this canonicalizer family reads.

All six fixture tools name it `path`, and the default below is the fixture's own
default for `list_directory`, so the gateway canonicalizes the same target the
upstream would open when the client omits it. A tool with a differently-named path
argument would canonicalize `"."` instead and be denied — fail-closed, and the
trigger for making this per-tool registry data rather than a constant.
"""
_DEFAULT_PATH: Final = "."

#: `_tech/05` §6. `NUL` is here as a DEVICE name; the null *byte* is step 2.
_RESERVED_NAMES: Final = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

#: Operations whose target legitimately does not exist yet, so only the PARENT is
#: required to resolve. `rename` is listed for completeness; no approved tool
#: produces one, and the day one does its source path needs its own resolution.
_CREATE_LIKE: Final[frozenset[Operation]] = frozenset(
    {"create", "overwrite", "append", "rename"}
)


class _Resolved(NamedTuple):
    """The configuration, resolved against the real filesystem once.

    Roots are ordered deepest-first so a nested root wins over its parent regardless
    of the order someone wrote them in the file.
    """

    base: Path
    roots: tuple[tuple[Path, RootConfig], ...]
    decoys: tuple[Path, ...]


@lru_cache(maxsize=4)
def _realpaths(
    base: str, root_paths: tuple[str, ...], decoys: tuple[str, ...]
) -> tuple[Path, tuple[Path, ...], tuple[Path, ...]]:
    """The ten or so `realpath` calls the configuration implies, done once.

    `_tech/05` §4: resolving the roots per request is wasted work on the hot path,
    and the benchmark publishes that number. Keyed on plain strings rather than on
    `CanonicalizeConfig` because a pydantic model's generated `__hash__` is invisible
    to pyright, and reaching for a cast to hide that would be hiding it from the
    reader too.

    Not an error when a root does not exist. Nothing inside a missing directory can
    resolve either, so the whole area denies with CANON_RESOLUTION_FAILED — which is
    fail-closed and immediately visible, whereas refusing to start would make a fresh
    clone (where `var/` is gitignored) unable to even load its configuration.
    """
    real_base = Path(os.path.realpath(base))
    return (
        real_base,
        tuple(Path(os.path.realpath(p)) for p in root_paths),
        tuple(Path(os.path.realpath(real_base / d)) for d in decoys),
    )


def _resolved(cfg: CanonicalizeConfig) -> _Resolved:
    """Pair each resolved root back with the entry it came from, deepest first."""
    base, root_paths, decoys = _realpaths(
        cfg.base,
        tuple(r.path for r in cfg.roots),
        cfg.sensitive_decoys,
    )
    roots = sorted(
        zip(root_paths, cfg.roots, strict=True),
        key=lambda pair: len(pair[0].parts),
        reverse=True,
    )
    return _Resolved(base=base, roots=tuple(roots), decoys=decoys)


# ===========================================================================
# Steps 1-8 — everything that happens before the filesystem is touched
# ===========================================================================


def decode_once(raw: str) -> str:
    """CANON-001. Decode exactly once; reject anything still encoded afterwards.

    `errors="strict"` is the whole of CANON-002 here: the default `errors="replace"`
    turns a malformed UTF-8 sequence into U+FFFD, which is the silent *repair* the
    requirement forbids — the canonical path would then describe a file the client
    never named.

    The residual check is what defeats double encoding without ever decoding twice.
    `%252e%252e%252f` decodes once to `%2e%2e%2f`, still matches, and is denied. A
    path legitimately containing a literal `%41` is denied with it; that is an
    accepted false positive against a synthetic fixture and it is published as one.

    It also makes a second pass *unobservable*, which the break pass established
    rather than assumed: `unquote` only rewrites `%XX` sequences, and by the time
    control reaches the return there are none left, so appending another call changes
    nothing for any input. The guard against decoding twice is therefore the residual
    check itself, not the number of calls a reader counts here.
    """
    try:
        decoded = urllib.parse.unquote(raw, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise _deny(
            ReasonCode.CANON_ENCODING_INVALID, "malformed percent-encoding"
        ) from e
    if _PERCENT_HEX.search(decoded):
        raise _deny(
            ReasonCode.CANON_ENCODING_INVALID,
            "percent-encoding remains after one decode pass",
        )
    return decoded


def _reject_control_characters(text: str, when: str) -> None:
    """CANON-002. Rejected, never stripped — a repaired path is a different path."""
    for ch in text:
        if ch == "\x7f" or ord(ch) < 0x20:
            raise _deny(
                ReasonCode.CANON_NULL_BYTE,
                f"control character U+{ord(ch):04X} in the supplied path ({when})",
            )


def _reject_hostile_syntax(text: str) -> None:
    """CANON-016. Path syntaxes this gateway refuses to canonicalize at all.

    Every one of these denotes something other than a plain file inside a root, or
    denotes it ambiguously:

    `\\\\.\\` `\\\\?\\`  Windows device namespace, and `//` is a UNC share
    `:`             a drive letter, or an alternate data stream (`notes.txt:hidden`)
    `CON`, `LPT1`   reserved device names, with or without an extension
    trailing `.`/` ` Win32 strips both, so `secret.txt.` opens `secret.txt`

    The trailing dot is the one worth understanding. Resolving it would be *safe*
    here — containment compares resolved paths, and `realpath` on Windows collapses
    it to the same file — but it resolves on Windows and fails on Linux, so the same
    corpus row would report two different reason codes on two machines. Refusing it
    everywhere is one behaviour, and no legitimate path in this fixture needs it.
    """
    for part in text.split("/"):
        if not part or part in (".", ".."):
            continue
        if ":" in part:
            raise _deny(
                ReasonCode.CANON_PATH_REJECTED,
                "':' in a path component (drive letter or alternate data stream)",
            )
        if part != part.rstrip(". "):
            raise _deny(
                ReasonCode.CANON_PATH_REJECTED,
                "path component ends in a dot or a space",
            )
        if part.split(".")[0].upper() in _RESERVED_NAMES:
            raise _deny(
                ReasonCode.CANON_PATH_REJECTED,
                f"reserved device name: {part.split('.')[0].upper()}",
            )


def _sanitize(raw: str, cfg: CanonicalizeConfig) -> str:
    """Steps 1-8. Returns a relative POSIX-separated path, or raises."""
    if len(raw) > cfg.max_path_length:
        raise _deny(
            ReasonCode.CANON_PATH_REJECTED,
            f"path is {len(raw)} characters, limit is {cfg.max_path_length}",
        )
    _reject_control_characters(raw, "as supplied")
    decoded = decode_once(raw)
    # Again after decoding: `%00` is a null byte the first pass could not see, and it
    # is the single most common truncation attack in this class.
    _reject_control_characters(decoded, "after decoding")

    text = unicodedata.normalize("NFC", decoded).replace("\\", "/")
    _reject_hostile_syntax(text)

    # CANON-007's first half, and the classic bug it names: `Path("/root") / "/etc"`
    # is `/etc`, so an absolute argument REPLACES the root instead of extending it.
    # Checked before the join rather than detected after it, and checked under both
    # flavours because `PureWindowsPath` alone accepts `/etc/passwd` as rootless and
    # `PurePosixPath` alone accepts `C:/Windows` as relative.
    if (
        PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
        or PureWindowsPath(text).drive
    ):
        raise _deny(ReasonCode.CANON_OUTSIDE_ROOT, "absolute path")
    return text


# ===========================================================================
# Steps 9-12 — the filesystem
# ===========================================================================


def _containing_root(p: Path, res: _Resolved) -> RootConfig | None:
    """CANON-007 / CANON-008. Segment-aware, on the RESOLVED path.

    `PurePath.is_relative_to` compares path components, which is why a root of
    `.../pub` does not contain `.../public-secrets`. `str.startswith` does, and
    substituting it is the most common path-traversal bug in production gateways —
    it is also the single edit that would make this whole module a no-op, so
    `test_canonicalize.py` breaks it deliberately and confirms the sibling-prefix
    case then fails.
    """
    for real_root, root in res.roots:
        if p.is_relative_to(real_root):
            return root
    return None


def _resolve(text: str, res: _Resolved) -> tuple[Path, Path]:
    """The real path, and the lexical one used only to explain a denial.

    `strict=False` resolves every symlink it can and leaves what does not exist
    alone; step 12 is what refuses a path that had to be left alone. A symlink loop
    or an unreadable component also lands here unresolved, and also fails step 12.

    The lexical path is `normpath` — pure string surgery, `..` collapsed without
    consulting the filesystem, which `_tech/05` §10 correctly calls a vulnerability
    when used for containment. **It is never used for containment.** Its only job is
    choosing between two reason codes: a path that is lexically inside a root but
    really outside it got there through a symlink, and CANON_SYMLINK_ESCAPE says so.
    Nothing is permitted on the strength of it.
    """
    candidate = res.base / text
    return Path(os.path.realpath(candidate)), Path(os.path.normpath(candidate))


def _require_existence(real: Path, operation: Operation) -> bool:
    """CANON-009, and the create-vs-overwrite input for CANON-012.

    Returns whether the target exists. A create-class operation legitimately targets
    a name that does not exist yet, so only its parent has to; every other operation
    needs the target itself. Failure is a denial, never a fallback to the unresolved
    string.

    `Path.exists()` swallows `OSError`, so a symlink loop, a permission failure and a
    missing component all arrive here as `False` — which is the correct answer to
    "did resolution produce something usable?" in all three cases.
    """
    if operation in _CREATE_LIKE:
        if not real.parent.is_dir():
            raise _deny(
                ReasonCode.CANON_RESOLUTION_FAILED,
                f"parent directory does not resolve: {real.parent}",
            )
        return real.exists()
    if not real.exists():
        raise _deny(ReasonCode.CANON_RESOLUTION_FAILED, f"does not resolve: {real}")
    return True


# ===========================================================================
# Pipeline surface
# ===========================================================================


def derive(
    req: CanonicalRequest, tgt: ResolvedTarget, cfg: CanonicalizeConfig
) -> DerivedAttributes:
    """Supplied path -> canonical identity + derived attributes, or raise.

    Every ambiguity is a denial. This module never repairs input (CANON-002).
    """
    if tgt.tool_name is None:
        return _no_resource(req)

    res = _resolved(cfg)
    raw = str(req.arguments.get(_PATH_ARG, _DEFAULT_PATH))
    real, lexical = _resolve(_sanitize(raw, cfg), res)

    root = _containing_root(real, res)
    if root is None:
        # Which of the two codes is cosmetic — both deny — but it is the difference
        # between "the client asked for something outside" and "something inside
        # pointed outside", and only the second implicates the fixture's own tree.
        raise _deny(
            ReasonCode.CANON_SYMLINK_ESCAPE
            if _containing_root(lexical, res) is not None
            else ReasonCode.CANON_OUTSIDE_ROOT,
            f"{real} is inside no approved root",
        )
    if any(real == d or real.is_relative_to(d) for d in res.decoys):
        # CANON-014. Ahead of policy on purpose: a sensitive location is denied for
        # every principal, so routing it through a rule that could be edited to say
        # otherwise adds a way to get it wrong and no way to get it right.
        raise _deny(ReasonCode.CANON_SENSITIVE_PATH, f"{real} is a sensitive location")

    exists = _require_existence(real, tgt.operation)
    canonical = real.as_posix()
    return DerivedAttributes(
        canonical_path=canonical,
        root=root.name,
        operation=_operation(tgt.operation, exists),
        classification=root.classification,
        exists=exists,
        # CANON-011: the pair is what lets an investigator correlate a decision to an
        # exact input without the audit log ever holding the input. `arg_hash` covers
        # the canonical path as well as the arguments, so it identifies the resource
        # policy actually authorised — unit 07 recomputes it before forwarding
        # (ROUTE-002), and a path that changed between the two stages breaks the
        # comparison rather than travelling.
        arg_hash=hashing.hash_obj({**req.arguments, "canonical_path": canonical}),
        raw_hash=hashing.sha256_hex(raw.encode("utf-8")),
    )


def _operation(registry_operation: Operation, exists: bool) -> Operation:
    """CANON-012. The registry says which class; existence splits create from overwrite.

    The split is racy by definition — that is the TOCTOU limitation this unit states
    rather than hides. It cannot upgrade a privilege: policy treats overwrite as at
    least as sensitive as create, so losing the race can only produce a stricter
    evaluation than the truth.
    """
    if registry_operation in ("create", "overwrite"):
        return "overwrite" if exists else "create"
    return registry_operation


def _no_resource(req: CanonicalRequest) -> DerivedAttributes:
    """`tools/list` names no tool and therefore no resource (unit 04's R0 target).

    The empty strings are the sentinel, and they are unambiguous because `RootConfig`
    refuses an empty name: no real root, and no real classification, can collide with
    them. Policy branches on `tool_name is None` long before it looks at a path.

    Inventing a placeholder path instead would be worse in both directions — one that
    happens to be inside a root grants discovery on the strength of a fiction, and one
    outside denies `tools/list` outright.
    """
    return DerivedAttributes(
        canonical_path="",
        root="",
        operation="read",
        classification="",
        exists=False,
        arg_hash=hashing.hash_obj({**req.arguments}),
        raw_hash=hashing.sha256_hex(b""),
    )


def audit_fields(drv: DerivedAttributes) -> JsonObject:
    """What stage 05 contributes to the record (spec §5, AUDIT-005).

    `operation` is written again here, over the registry's value from stage 04, and
    that is deliberate: this is the refined one, and the refined one is what policy
    evaluated. A record showing `overwrite` where policy saw `create` would describe
    a decision nobody made.

    `canonical_path` is the one full value in the record. It is the resource identity
    the whole evidence chain turns on, and it is derived from the approved roots
    rather than from client input; the client's own string is present only as
    `raw_hash` (CONV-012).
    """
    return {
        "canonical_resource": drv.canonical_path,
        "classification": drv.classification,
        "operation": drv.operation,
        "arg_hash": drv.arg_hash,
        "raw_hash": drv.raw_hash,
    }


def _deny(code: ReasonCode, detail: str) -> CanonicalizationDenial:
    return CanonicalizationDenial(code, detail=detail)


__all__ = ["IMPLEMENTED_DECODE_RULE", "audit_fields", "decode_once", "derive"]
