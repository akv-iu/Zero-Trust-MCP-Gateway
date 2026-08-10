# TECH-05 — `svc-canonicalizer-fs`

**Pairs with:** [`_specs/05-svc-canonicalizer-fs.md`](../_specs/05-svc-canonicalizer-fs.md)
**Module:** `gateway/canonicalize/fs.py`

---

## 1. Algorithm

Fixed order. Every step can only reject or narrow; none may widen. This is the order
`gateway/canonicalize/fs.py` implements; where it differs from the draft below, §3 and
§5 say why.

```
1  length gate                                     CANON_PATH_REJECTED
2  reject NUL and controls, as supplied            CANON_NULL_BYTE
3  decode exactly once (documented)                CANON_ENCODING_INVALID
4  reject residual encoding                        CANON_ENCODING_INVALID
5  reject NUL and controls, after decoding         CANON_NULL_BYTE
6  NFC normalize, then `\` -> `/`
7  reject device namespaces / UNC / ADS / reserved
   names / trailing dot or space                   CANON_PATH_REJECTED
8  reject absolute, drive-qualified, UNC            CANON_OUTSIDE_ROOT
9  join to base, resolve as far as the fs allows
10 containment, segment-aware      CANON_OUTSIDE_ROOT / CANON_SYMLINK_ESCAPE
11 sensitive decoy check                            CANON_SENSITIVE_PATH
12 existence, per operation class                   CANON_RESOLUTION_FAILED
13 derive operation/classification/exists/hashes
```

Two changes from the first draft, both load-bearing:

**The control-character check runs twice.** `%00` is invisible before decoding, and it
is the most common truncation attack in this class. One pass would catch the literal
and miss the encoded one.

**Containment (10) comes before existence (12).** See §3.

---

## 2. Step 3 — decode exactly once (CANON-001)

The single most error-prone requirement in the project. Get the rule written down and tested before writing the code.

**Rule (document verbatim in `docs/threat-model.md`):**

> A supplied path is percent-decoded exactly once using UTF-8. After that single pass, any remaining `%` followed by two hex digits causes rejection. No other decoding is applied — no unicode-escape, no HTML entity, no backslash escape.

```python
def decode_once(raw: str) -> str:
    try:
        decoded = urllib.parse.unquote(raw, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise CanonicalizationDenial(CANON_ENCODING_INVALID)
    if _PERCENT_HEX.search(decoded):  # re.compile(r"%[0-9A-Fa-f]{2}")
        raise CanonicalizationDenial(CANON_ENCODING_INVALID)
    return decoded
```

Note `unquote` with `errors="strict"` — the default `errors="replace"` silently turns malformed sequences into U+FFFD, which is exactly the "repair" `CANON-002` forbids.

Residual-encoding rejection is what defeats double encoding: `%252e%252e%252f` decodes once to `%2e%2e%2f`, which still matches `_PERCENT_HEX` → denied. A path legitimately containing a literal `%41` is denied too; that is an accepted false positive in a synthetic fixture, and it is recorded in the report's limitations.

Also reject after decoding: `\x00`, any `ord(c) < 0x20`, and `\x7f`.

---

## 3. Steps 9 and 12 — resolution, and why containment comes first

**Corrected from the original draft.** It resolved with `strict=True` *before* checking
containment, which produces a different reason code for the same attack depending on
whether the target happens to exist:

```
../../../etc/shadow   on a host that has it  -> CANON_OUTSIDE_ROOT
../../../etc/shadow   on a host that has not -> CANON_RESOLUTION_FAILED
```

Two problems. The reason code becomes an existence oracle across the security
boundary — a prober learns what is installed from the code it gets back. And the
corpus is a **published artifact that must score identically on WSL2 and on Windows**,
where `/etc/passwd` exists on exactly one. The second is decisive: a row whose expected
reason depends on the developer's machine is not evidence. `CANON-017` now states the
ordering.

```python
def _resolve(text: str, res: _Resolved) -> tuple[Path, Path]:
    candidate = res.base / text
    return Path(os.path.realpath(candidate)), Path(os.path.normpath(candidate))


def _require_existence(real: Path, operation: Operation) -> bool:
    if operation in _CREATE_LIKE:  # create/overwrite/append/rename
        if not real.parent.is_dir():
            raise _deny(CANON_RESOLUTION_FAILED, ...)
        return real.exists()
    if not real.exists():
        raise _deny(CANON_RESOLUTION_FAILED, ...)
    return True
```

- `os.path.realpath(strict=False)` resolves every symlink it can and leaves what does not exist alone. It gives up nothing: a symlink anywhere in the *existing* prefix is still resolved, and the components it leaves alone are by definition the ones that do not exist — so they cannot be symlinks and cannot move the path anywhere. `CANON-004` still holds for every component.
- The existence gate at step 12 is what refuses everything `strict=True` would have refused. A symlink loop, a permission failure and a missing component all arrive at `Path.exists()` as `False`, because it swallows `OSError` — which is the correct answer to "did resolution produce something usable?" in all three cases.
- Create-class operations require only the **parent** to resolve. Requiring the leaf would refuse every legitimate `write_file` to a new name; requiring nothing would let a create into a nonexistent directory look like a success.
- `Path / rel` where `rel` is absolute **replaces** the base in `pathlib`. That is the classic absolute-path-escape bug, so it is checked *before* the join, under both `PurePosixPath` and `PureWindowsPath` — the first alone treats `C:/Windows` as relative, the second alone treats `/etc/passwd` as rootless.
- `strict=True` is not used anywhere. `os.path.ALLOW_MISSING` (Python 3.13) would express step 9 more precisely, and is deliberately not used either: `requires-python` is `>=3.12`, and the existence gate makes the difference unobservable.

The **lexical** path returned alongside is `os.path.normpath` — pure string surgery,
`..` collapsed without consulting the filesystem, which §10 correctly calls a
vulnerability when used for containment. It is never used for containment. Its only
job is choosing between two reason codes: a path lexically inside a root but really
outside it got there through a symlink, and `CANON_SYMLINK_ESCAPE` says so. Nothing is
permitted on the strength of it.

---

## 4. Step 10 — containment (CANON-007, CANON-008)

```python
root = _containing_root(real, res)
if root is None:
    raise _deny(
        CANON_SYMLINK_ESCAPE if _containing_root(lexical, res) else CANON_OUTSIDE_ROOT,
        ...,
    )
```

`PurePath.is_relative_to` compares **path components**, so `.../pub` does not contain `.../public-secrets` — spec test 11 passes for free. Never use `str.startswith`; that single substitution is the most common path-traversal bug in production gateways, and it is the one break in the pass that this module could not survive.

There are **several** roots — one per top-level directory of the fixture — and the answer is which one, not whether. `_containing_root` returns the `RootConfig`, because `classification` and the per-operation flags ride on it. Roots are ordered deepest-first, so a nested root wins over its parent regardless of the order someone wrote them in the file.

Resolved root paths are computed once and memoised (`_realpaths`, `lru_cache`), keyed on the configured strings rather than on the `CanonicalizeConfig` — a pydantic model's generated `__hash__` is invisible to pyright, and a cast to hide that from the type checker would hide it from the reader too.

Distinguishing the two reason codes is cosmetic but useful in the report; it is determined by comparing the pre-resolution (`normpath`) and post-resolution (`realpath`) paths rather than by calling `is_symlink()` on each component — fewer syscalls, and it catches intermediate links.

---

## 5. Case sensitivity (CANON-005) — no probe, and that is stronger

**Corrected from the original draft**, which proposed touching a file at startup to
learn whether the filesystem folds case, then casefolding deny-rule comparisons on
platforms that do. Neither half is needed, and the reason is worth stating because it
generalises.

Containment compares a **resolved path to a resolved root**, and `realpath` returns the
true on-disk spelling of every component that exists. Measured on the Windows
development machine:

```
realpath(tmp/public/doc.txt)  where the directory is `Public` and the file `Doc.txt`
  -> C:\...\Public\Doc.txt
```

So on a case-folding filesystem `PUBLIC/DOCUMENTATION.TXT` and `public/documentation.txt`
canonicalize to the identical string — distinct-case paths are treated as identical for
containment, which is exactly what `CANON-005` asks for, with no casefolding logic at
all. On a case-sensitive filesystem the wrong-case path names nothing and is denied at
step 12. Both are safe; neither is an assumption about the platform, which is what
`CANON-005`'s "the actual semantics of the target filesystem, not an assumption" means.

Components that do **not** exist keep the supplied case. That is harmless: a name that
is not on disk cannot collide with one that is.

A probe would also have been a startup-time write into the fixture tree — a side effect
in the protected system, performed by the gateway, which the oracle would have to be
taught to ignore. `test_canonicalize.py::test_9_...` detects case folding locally and
asserts whichever outcome the platform's semantics imply, so the property is still
tested on both kinds of filesystem; the benchmark's environment block should record
which one produced a given run.

---

## 6. Windows specifics — applied on every platform

Reject outright — resolving these is not worth the attack surface. `CANON-016`.

**Unconditionally, not `if os.name == "nt"`.** A rule that fires only on Windows makes
the same corpus row report `CANON_PATH_REJECTED` on the developer's laptop and
something else in CI, which is not a measurement. Every rule here can only ever deny
more, and none of them can name a file this fixture contains. `\` is the one exception:
it is **translated** to `/` rather than rejected, because `CANON-006` requires a
separator variant to produce the same canonical result as its equivalent. On POSIX that
costs the ability to name a file with a literal backslash in it — an accepted false
positive, published as one.

| Pattern | Example |
|---|---|
| Device namespace | `\\.\`, `\\?\` |
| UNC path | `\\server\share` |
| Alternate data stream | `file.txt:hidden` (a `:` after position 1) |
| Reserved device names | `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` (any extension) |
| Trailing dot or space | `secret.txt.`, `secret.txt ` — Windows strips these |
| 8.3 short names | `CONFID~1` — see below |

Trailing-dot/space stripping is a genuine bypass: `confidential.` and `confidential` are the same directory to Win32 but different strings to a naive rule. Reject any component with a trailing `.` or space.

Resolving the trailing dot would in fact be *safe* in this design — containment compares
resolved paths and `realpath` collapses it to the same file — but it resolves on Windows
and fails on Linux, so the same corpus row would carry two reason codes. Refusing it
everywhere is one behaviour.

**8.3 short names are not specially handled.** `os.path.realpath` on the development
machine expands them along with everything else, because a short name is just another
name the directory holds; it therefore lands inside the same root as its long form and
gets the same classification. There is no separate check and no probe. If a filesystem
is ever found where the short form resolves somewhere the long form does not, that is a
containment bug and belongs in the Hypothesis strategy, not in a special case.

`Path.resolve()` on Windows does resolve reparse points, which is what makes spec tests
6 and 7 work there — when the platform will create a symlink at all. This developer's
machine will not (no Developer Mode, not elevated), so those rows report SKIPPED.

---

## 7. Derived attributes

```python
operation = tgt.operation  # from the REGISTRY, never inferred
if operation in ("create", "overwrite"):  # CANON-012
    operation = "overwrite" if exists else "create"

classification = root.classification  # the CONTAINING root's, CANON-013
arg_hash = hash_obj({**req.arguments, "canonical_path": canonical})
raw_hash = sha256_hex(raw_path.encode("utf-8"))
```

The create/overwrite split depends on `exists`, which is racy by definition — that is exactly the TOCTOU limitation the spec states rather than pretends away. Policy treats overwrite as at least as sensitive as create, so the race cannot upgrade privilege.

**No `classification_map`.** The draft keyed one on the first path segment under a
single root. There is one root per top-level directory instead, each carrying its own
`classification`, so the mapping *is* the root list — one place to read, one place to
review, and `DerivedAttributes.root` becomes a name a reader recognises rather than a
path prefix. Same source (`fixtures/manifest.py`'s layout, under version control), one
fewer structure to keep in sync; `test_canonicalize.py::test_15b_...` asserts the config
and the manifest agree.

`arg_hash` covers the canonical path as well as the arguments, so it identifies the
resource **policy actually authorized**. Unit 07 recomputes it from `drv` before
forwarding (`ROUTE-002`), so a path that changed between stages breaks the comparison
rather than travelling.

For the tool-less `tools/list` target, `canonical_path`, `root` and `classification` are
all `""`. That is the sentinel, and it is unambiguous because `RootConfig` refuses an
empty name. Inventing a placeholder path would be wrong in both directions — one inside
a root grants discovery on a fiction, one outside denies `tools/list` outright.

---

## 8. Startup self-check (CANON-015)

`Config.self_check(config_path)`, run by `startup.load_all` before anything is spawned
or opened. Uses the same `is_relative_to` comparison as the request path, so a bug in
containment shows up here too.

The signature takes the config path because **a `Config` does not know where it came
from**, and CANON-015 names the gateway's own configuration first — without the
argument, the one item at the top of the list was the one item the check could not see.
`registry_path` and `audit.path` come off the model. `policy_bundle_path` is not in the
draft's list because there is no such key: OPA is a sidecar with its own bundle, and
`self_check` deliberately reads only what `gateway/config.py` owns — a config method
reaching into another file to validate itself is how the two get coupled.

A startup `check_decode_rule(cfg)` was written here and then **deleted**. It compared
`cfg.decode_rule_version` to `IMPLEMENTED_DECODE_RULE`, which is theatre twice over:
the config field is a single-member `Literal`, so pydantic refuses any other value
before the check can run, and the comparison was blind to the failure that actually
occurs — someone edits `decode_once` and leaves the version string alone, at which
point both sides still agree. `hashing.FINGERPRINT_VERSION` was bitten by exactly that.
What catches it is a **golden vector set keyed on the version**
(`test_canonicalize.py::DECODE_GOLDEN`), which is the same control that caught it for
fingerprints. Ponytail pass, unit 05.

---

## 9. Tests

- Every row of spec §9 as a table-driven case, each asserting both the reason code and (via the oracle) that the fixture observed nothing.
- **Hypothesis strategy** — compose adversarial paths from a segment alphabet: `["..", ".", "%2e%2e", "%252e", "\\", "/", "\x00", "public", "confidential", "escape_link", "CON", "x."]` joined at random lengths. Invariant: `resolve()` either raises or returns a path satisfying `is_relative_to(root_real)`. Never both-not.
- The legitimate corpus (spec test 15) gets equal weight — every tool × every permitted path, asserting success. The report publishes a false-positive rate and this is its only source.
- Symlink fixtures: `build_tree` already ships `traps/`, and `links_available()` reports whether the platform created them. `pytest.skip` where it did not (Windows needs Developer Mode or admin). A skip must be **reported as skipped** in the benchmark (`FIX-003`), never counted as a pass — and because three rows can skip, the symlink-free duplicates matter: `CANON_RESOLUTION_FAILED` has a missing-file row and the in-root-link control has a plain in-root read.
- The test config is the SHIPPED root layout with its paths repointed at `tmp_path`, not a hand-written one. A test that invents its own roots proves the code works and says nothing about the artifact — the lesson `test_shipped_config.py` exists for.
- The wiring test drives `pipeline.handle` and reads the record off disk. Every other audit assertion calls `fs.audit_fields()` itself, so deleting the `builder.set(...)` line from the pipeline would leave them all green. That failure shape has now been found four times in this project.

---

## 10. Gotchas

- `os.path.normpath` collapses `..` **lexically**, before symlinks — using it for containment is a vulnerability. Only `resolve()`/`realpath()` are trustworthy. It is used here for exactly one thing, and never for containment: see §3.
- `os.path.realpath(strict=False)` silently succeeds for nonexistent paths. That is *relied on* at step 9 and made safe by the existence gate at step 12 — see §3. What must never happen is relying on it without step 12.
- Unicode: NFC normalize after decoding, and be aware that macOS HFS+/APFS normalizes to NFD on disk — the resolved path you get back may not equal the string you passed. Compare resolved-to-resolved, never resolved-to-input.
- Do not "fix" a path. Every ambiguity is a denial. The moment this module repairs input, its output stops being a faithful canonicalization of what the client asked for.
