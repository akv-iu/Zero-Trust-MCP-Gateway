# TECH-05 — `svc-canonicalizer-fs`

**Pairs with:** [`_specs/05-svc-canonicalizer-fs.md`](../_specs/05-svc-canonicalizer-fs.md)
**Module:** `gateway/canonicalize/fs.py`

---

## 1. Algorithm

Fixed order. Every step can only reject or narrow; none may widen.

```
1. type/length gate        str, non-empty, len <= max_path_length
2. reject NUL and controls           -> CANON_NULL_BYTE
3. decode exactly once (documented)  -> CANON_ENCODING_INVALID
4. reject residual encoding          -> CANON_ENCODING_INVALID
5. NFC normalize
6. reject Windows device namespaces / ADS / 8.3 shorts (if applicable)
7. join to root, resolve real path   -> CANON_RESOLUTION_FAILED
8. containment check (segment-aware) -> CANON_OUTSIDE_ROOT / CANON_SYMLINK_ESCAPE
9. sensitive decoy check             -> CANON_SENSITIVE_PATH
10. derive operation/classification/exists/hashes
```

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

## 3. Step 7 — resolution

Two cases, because create operations legitimately target a nonexistent leaf.

```python
def resolve_target(root: Path, rel: str, operation: str) -> tuple[Path, bool]:
    candidate = root / rel  # rel may be absolute -> handled below
    if PurePath(rel).is_absolute() or (os.name == "nt" and PureWindowsPath(rel).drive):
        raise CanonicalizationDenial(CANON_OUTSIDE_ROOT)
    if operation in ("create", "overwrite", "append", "rename"):
        parent = candidate.parent.resolve(strict=True)  # parent MUST exist and resolve
        real = parent / candidate.name
        exists = real.exists()
    else:
        real = candidate.resolve(strict=True)
        exists = True
    return real, exists
```

- `Path.resolve(strict=True)` raises `OSError` on a missing component, a symlink loop (`ELOOP`), or a permission failure — all map to `CANON_RESOLUTION_FAILED` (`CANON-009`). Catch `OSError`, never `except Exception`.
- For create-class operations, **resolve the parent strictly** and append the leaf name. This is the only correct way to canonicalize a path that does not yet exist; resolving the whole thing non-strictly would let a symlinked parent escape undetected.
- Reject the leaf name if it is `.`, `..`, or contains a separator — after parent resolution, the leaf must be a single component.
- `Path / rel` where `rel` is absolute **replaces** the root in `pathlib`. That is the classic absolute-path-escape bug, so check `is_absolute()` (and the Windows drive/UNC case) *before* joining.

`resolve()` resolves every component's symlinks, not just the last (`CANON-004`), which covers spec test 7.

---

## 4. Step 8 — containment (CANON-007, CANON-008)

```python
if not real.is_relative_to(root_real):
    raise CanonicalizationDenial(
        CANON_SYMLINK_ESCAPE if _had_symlink(candidate) else CANON_OUTSIDE_ROOT
    )
```

`PurePath.is_relative_to` compares **path components**, so `/workspace/pub` does not contain `/workspace/public-secrets` — spec test 11 passes for free. Never use `str.startswith`; that single substitution is the most common path-traversal bug in production gateways.

`root_real` is `root.resolve(strict=True)` computed once at startup and stored — resolving it per request is wasted work and creates a TOCTOU window on the root itself.

Distinguishing the two reason codes is cosmetic but useful in the report; determine it by comparing the pre-resolution and post-resolution paths rather than by calling `is_symlink()` on each component (fewer syscalls, and it catches intermediate links).

---

## 5. Case sensitivity (CANON-005)

Probe once at startup rather than assuming from `os.name`— macOS is usually case-insensitive, Linux usually not, and both have exceptions:

```python
def probe_case_sensitivity(root: Path) -> bool:
    p = root / ".case_probe_XYZ"
    p.touch()
    try:
        return not (root / ".case_probe_xyz").exists()
    finally:
        p.unlink()
```

On a case-**insensitive** filesystem, deny-rule matching must casefold both sides, otherwise `/fixture/Confidential/x` evades a rule written against `confidential`. On a case-sensitive one, do not casefold — that would conflate genuinely distinct files.

Store the probe result in `Deps` and record it in the benchmark report's environment block; it changes what the corpus proves.

`CANON-005`'s "behave conservatively when undeterminable": if the probe fails, assume case-insensitive (the stricter option for deny rules).

---

## 6. Windows specifics

Reject outright — resolving these is not worth the attack surface:

| Pattern | Example |
|---|---|
| Device namespace | `\\.\`, `\\?\` |
| UNC path | `\\server\share` |
| Alternate data stream | `file.txt:hidden` (a `:` after position 1) |
| Reserved device names | `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` (any extension) |
| Trailing dot or space | `secret.txt.`, `secret.txt ` — Windows strips these |
| 8.3 short names | `CONFID~1` — probe-detect if `GetLongPathName` differs |

Trailing-dot/space stripping is a genuine bypass: `confidential.` and `confidential` are the same directory to Win32 but different strings to a naive rule. Reject any component with a trailing `.` or space.

`Path.resolve()` on Windows does resolve reparse points, but verify the 8.3 case on the actual dev machine — short-name generation may be disabled, in which case document that and move on.

---

## 7. Derived attributes

```python
operation = TOOL_OPERATIONS[target.tool_name]  # from registry, not inferred (CANON-012)
if operation in ("create", "overwrite") and exists:
    operation = "overwrite"
elif operation in ("create", "overwrite"):
    operation = "create"

classification = cfg.classification_map[_top_segment(real.relative_to(root_real))]
arg_hash = hash_obj(dict(req.arguments) | {"canonical_path": str(real)})
raw_hash = sha256_hex(raw_path.encode("utf-8"))
```

The create/overwrite split depends on `exists`, which is racy by definition — that is exactly the TOCTOU limitation the spec states rather than pretends away. Policy treats overwrite as at least as sensitive as create, so the race cannot upgrade privilege.

`classification_map` is keyed on the first path segment under the root (`public`, `workspace`, `confidential`, `production`, `decoys`, `traps`), derived from layout and never from content (`CANON-013`).

---

## 8. Startup self-check (CANON-015)

```python
for protected in (
    cfg.config_path,
    cfg.registry_path,
    cfg.audit_path,
    cfg.policy_bundle_path,
):
    for root in roots_real:
        if protected.resolve().is_relative_to(root):
            raise ConfigError(f"{protected} is inside approved root {root}")
```

Run before readiness. Uses the same `is_relative_to` comparison as the request path, so a bug in containment shows up here too.

---

## 9. Tests

- Every row of spec §9 as a table-driven case, each asserting both the reason code and (via the oracle) that the fixture observed nothing.
- **Hypothesis strategy** — compose adversarial paths from a segment alphabet: `["..", ".", "%2e%2e", "%252e", "\\", "/", "\x00", "public", "confidential", "escape_link", "CON", "x."]` joined at random lengths. Invariant: `resolve()` either raises or returns a path satisfying `is_relative_to(root_real)`. Never both-not.
- The legitimate corpus (spec test 15) gets equal weight — every tool × every permitted path, asserting success. The report publishes a false-positive rate and this is its only source.
- Symlink fixtures: create in `conftest` via `Path.symlink_to`, `pytest.skip` on `OSError` (Windows needs Developer Mode or admin). A skip must be **reported as skipped** in the benchmark (`FIX-003`), never counted as a pass.

---

## 10. Gotchas

- `os.path.normpath` collapses `..` **lexically**, before symlinks — using it for containment is a vulnerability. Only `resolve()`/`realpath()` are trustworthy.
- `Path.resolve(strict=False)` on Windows silently succeeds for nonexistent paths; the create-path branch in §3 exists to avoid depending on that.
- Unicode: NFC normalize after decoding, and be aware that macOS HFS+/APFS normalizes to NFD on disk — the resolved path you get back may not equal the string you passed. Compare resolved-to-resolved, never resolved-to-input.
- Do not "fix" a path. Every ambiguity is a denial. The moment this module repairs input, its output stops being a faithful canonicalization of what the client asked for.
