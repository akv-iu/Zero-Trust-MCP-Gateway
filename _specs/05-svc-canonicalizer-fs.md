# SPEC-05 — `svc-canonicalizer-fs`

**Role:** Filesystem path canonicalization and derived policy attributes
**Phase:** v1 · **Build order:** 8th
**Depends on:** `04-svc-registry`
**Consumed by:** `06-svc-policy-broker`
**Source lineage:** `REQ-FS-001`, `REQ-FS-002`, `REQ-FS-003`, `REQ-FS-006`, `REQ-GUARD-002`, `REQ-GUARD-003`

---

## 1. Purpose

Policy must never evaluate ambiguous text. This unit converts a client-supplied path string into a single canonical resource identity, plus the derived attributes policy needs (operation class, root, classification), or rejects it.

It is the only canonicalizer family in v1. SQL and URL canonicalization are cut (`90-deferred-register.md`) — one family, done thoroughly and tested exhaustively, is worth more as evidence than three done partially.

---

## 2. Stated limitation — read this before implementing

**The primary filesystem control is the sandbox mount (unit 10), not this unit.**

Canonicalizing a path and then handing a string to a separate process is inherently racy: the filesystem can change between resolution and use. That TOCTOU window cannot be closed at the gateway. Path canonicalization is **defense in depth and a policy-input requirement** — it is what lets policy reason about a stable resource identity — and it is not a race-free guarantee.

v1 tests canonicalization correctness exhaustively and **does not claim TOCTOU safety**. The archival source document hid this behind "where practical" (`REQ-FS-006`); this spec states it plainly, and the README and threat model must state it too. A limitation stated precisely is stronger evidence than a capability claimed loosely.

---

## 3. In scope

- Decoding, normalizing, and resolving a supplied path to a real canonical path.
- Verifying containment within an approved root.
- Classifying the operation (read / create / overwrite / append / rename / delete).
- Emitting derived attributes and hashes for policy and audit.

## 4. Out of scope

- The authorization decision — unit 06 consumes these attributes.
- Sandbox enforcement — unit 10 owns the mount.
- SQL, URL/SSRF, shell canonicalization — cut.
- Atomic writes, backups, versioning (`REQ-FS-005`) — cut; the fixture's write surface is small and synthetic.

---

## 5. Contract

**Input:** resolved target and validated arguments from unit 04.
**Output on success:** **derived attributes**, attached alongside the canonical request (never mutating it, per `PROTO-006`):

| Attribute | Meaning |
|---|---|
| `canonical_path` | The fully resolved real path |
| `root` | Which approved root contains it |
| `operation` | `read` \| `create` \| `overwrite` \| `append` \| `rename` \| `delete` |
| `classification` | Fixture-derived label, e.g. `public` \| `confidential` \| `production` |
| `arg_hash` | Hash over normalized arguments |
| `raw_hash` | Hash over the argument as supplied, for investigation without storing it |
| `exists` | Whether the target currently exists — affects create-vs-overwrite |

**Output on failure:** terminal rejection with a `CANON_*` reason code.

---

## 6. Requirements

### 6.1 Resolution

**CANON-001 (`REQ-FS-002`)** — Decoding MUST apply **exactly once**, under a documented rule. Double decoding is a vulnerability; decoding zero times is a vulnerability. The rule MUST name which encodings are decoded and MUST reject input that still contains encoded path-significant characters after that single pass.

**CANON-002 (`REQ-FS-002`)** — Malformed encodings, null bytes, and embedded control characters MUST be rejected, never stripped or repaired. Repair is a normalization ambiguity and ambiguity is a denial.

**CANON-003 (`REQ-FS-002`)** — `.` and `..` segments MUST be resolved. Resolution MUST occur against the real filesystem, not by string manipulation alone.

**CANON-004 (`REQ-FS-002`)** — Symbolic links and platform-equivalent reparse points MUST be resolved to their real target. **Every** component of the path is resolved, not only the final one.

**CANON-005 (`REQ-FS-002`)** — Case normalization MUST follow the actual semantics of the target filesystem, not an assumption. Where case sensitivity cannot be determined reliably, the unit MUST behave conservatively — treat distinct-case paths as potentially identical for containment checks, so case cannot be used to escape a deny rule.

**CANON-006 (`REQ-FS-002`)** — Platform path separators MUST both be handled on platforms that accept both. A separator variant MUST NOT produce a different canonical result than its equivalent.

**CANON-007 (`REQ-FS-001`, `REQ-FS-002`)** — Containment MUST be verified against the **final resolved real path**, never against the supplied string, and never by prefix comparison on unresolved text. A resolved path outside every approved root is a denial.

**CANON-008** — Containment MUST NOT be satisfiable by a sibling-prefix collision: a root of `/workspace/pub` MUST NOT contain `/workspace/public-secrets`. Boundary comparison is path-segment-aware.

**CANON-009** — Resolution failure of any kind — nonexistent intermediate component where resolution requires one, permission error, loop in symlinks, exceeded resolution depth — MUST be a denial (`CONV-004`), never a fallback to the unresolved string.

**CANON-016** — A path whose *syntax* names something other than an unambiguous file MUST be refused before the filesystem is consulted: device namespaces and UNC shares, a `:` in any component (a drive letter or an alternate data stream), reserved device names (`CON`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with or without an extension), and a component ending in a dot or a space. The refusal MUST be unconditional rather than platform-conditional: a rule that fires only on Windows makes the same corpus row mean two different things on two machines, and every one of these can only ever deny more.

**CANON-017** — Containment (`CANON-007`) MUST be evaluated **before** existence (`CANON-009`). A path outside every approved root MUST report the boundary it crossed whether or not its target happens to exist. Ordering them the other way turns the reason code into an existence oracle across the security boundary and makes a published corpus row's expected reason depend on what is installed on the host.

**CANON-018** — Client-supplied relative paths MUST be resolved against the same base the upstream server uses. Where the two differ, the gateway canonicalizes one resource and the upstream acts on another: an allow whose audit record names a resource that was never touched, and a side effect nobody authorized. Nothing at runtime can detect this, so it MUST be asserted where both configurations are visible.

### 6.2 Derived attributes

**CANON-010 (`REQ-GUARD-002`)** — Policy MUST receive `canonical_path` and derived attributes. The raw supplied string MUST NOT be part of the policy input.

**CANON-011 (`REQ-GUARD-002`)** — Both `arg_hash` and `raw_hash` MUST be retained so an investigator can correlate a decision to an exact input without the audit log storing sensitive values (`CONV-012`).

**CANON-012 (`REQ-FS-005`)** — The operation class MUST distinguish create, overwrite, append, rename, and delete. Policy expresses different rules for each; collapsing them into "write" loses the distinction that makes the fixture demo meaningful.

**CANON-013 (`REQ-FS-003`)** — Classification MUST derive from the approved root and fixture layout under version control — not from file content, and not from anything the client supplies.

### 6.3 Sensitive locations

**CANON-014 (`REQ-FS-003`)** — Default policy MUST deny sensitive locations — SSH keys, cloud credentials, environment-secret files, browser profiles, package-manager tokens, OS configuration, and the gateway's own configuration. In v1 these are represented by **synthetic decoys inside the fixture**, never real paths, so the test corpus can exercise the rule without any real sensitive location being reachable.

**CANON-015** — The gateway's own configuration, registry file, policy bundle, and audit output MUST NOT be within any approved root. Startup MUST fail if they are — a self-protecting check, verified rather than assumed.

---

## 7. Failure modes

| Condition | Reason code |
|---|---|
| Malformed encoding / still-encoded after one pass | `CANON_ENCODING_INVALID` |
| Null byte or control character | `CANON_NULL_BYTE` |
| Device namespace, UNC, ADS, reserved device name, trailing dot or space, over-length (`CANON-016`) | `CANON_PATH_REJECTED` |
| Resolved path outside every approved root | `CANON_OUTSIDE_ROOT` |
| Symlink resolves outside an approved root | `CANON_SYMLINK_ESCAPE` |
| Symlink loop or resolution depth exceeded | `CANON_RESOLUTION_FAILED` |
| Resolution error (permission, unreadable component, target absent where the operation requires one) | `CANON_RESOLUTION_FAILED` |
| Path is a sensitive decoy location | `CANON_SENSITIVE_PATH` |
| Gateway config inside an approved root | startup fails |
| `decode_rule_version` naming a rule the build does not implement | config refuses to load (single-member `Literal`) |

`CANON_OPERATION_UNKNOWN` was in this table and is **removed**. The operation class arrives on `ResolvedTarget.operation`, a required member of a closed literal the registry loader has already validated, and unit 05 handles every member — a tool whose operation is missing or misspelled fails startup as a `ConfigError`. No request reaches the code, and `CONV-010` says a code no scenario can produce is removed rather than documented. Its revival trigger is in `gateway/errors.py`: an approved tool whose operation must be derived from *arguments* rather than from the registry.

---

## 8. Configuration surface

`base` — the directory client-supplied relative paths are resolved against (`CANON-018`); approved roots with per-root read/create/overwrite/append/rename/delete permissions; decode rule version; maximum path length; sensitive-decoy path list.

A root is an area the gateway is willing to **name**; the per-operation flags say what may be done there and are **policy input**, not checks unit 05 performs. Classification is the containing root's, which is what makes it derive from layout under version control (`CANON-013`) — there is no separate classification map, and a directory holding data nobody may touch is still a root, with every flag false. Leaving such a directory out of the roots instead would give "you asked for confidential data" and "you named a directory that does not exist" one reason code, and only the first is a finding.

`max_resolution_depth` was here and is **removed**: symlink depth is enforced by the operating system (`ELOOP`) and surfaced as `CANON_RESOLUTION_FAILED`, and a gateway-side counter would require the hand-rolled component walk §10 forbids. A configured limit nothing enforces fails `CONV-015` more loudly than a missing one.

---

## 9. Acceptance tests

The attack class here is the corpus's largest and the one reviewers recognize instantly. Every row gets both a hand-written case and Hypothesis coverage.

1. Plain traversal — `../` escaping the root.
2. Encoded traversal — percent-encoded separators and dot segments.
3. Double-encoded traversal — must be rejected, and must not be decoded twice into a valid path.
4. Null byte truncation.
5. Absolute-path escape — a fully qualified path outside the root.
6. Symlink escape — a link inside the root pointing outside it.
7. Symlink escape via an **intermediate** component, not the final one.
8. Symlink loop.
9. Case variants on the target filesystem's actual semantics.
10. Separator variants where the platform accepts both.
11. Sibling-prefix collision (`CANON-008`).
12. Unicode normalization variants that resolve to the same file.
13. Trailing separators, repeated separators, and `.` segments resolving to the same canonical path.
14. Every sensitive decoy is denied for every principal.
15. **Legitimate cases pass** — the false-positive side of the corpus is tested with equal weight; a canonicalizer that denies everything scores perfectly on attacks and is worthless.
16. Every denial is confirmed by the oracle: the fixture observed no read, no write, no stat of the escaped target.
17. Startup fails when an approved root would contain the gateway's config or audit output.
18. Hypothesis generates path and encoding variants from a recorded seed; every generated case resolves inside a root or is denied — never resolves outside a root and is allowed.
19. Every syntax `CANON-016` names is refused, on every platform.
20. A **golden vector set per decode-rule version** pins what `CANON-001`'s rule *does*, so changing `decode_once` without bumping the version fails; and `canonicalize.base` is asserted equal to the upstream's resolution base (`CANON-018`).

All twenty live in `tests/unit/test_canonicalize.py`, except 20's base assertion, which is in `tests/unit/test_shipped_config.py` — it is a property of the shipped *pair* of configurations, and putting it in the gateway's own tests would mean teaching `gateway/` the fixture's environment variable.

Tests 6, 7 and 8 need symlinks. Where the platform refuses to create them they are reported **SKIPPED** and never counted as passes (`FIX-003`); test 15's in-root link and the `CANON_RESOLUTION_FAILED` row are duplicated in symlink-free form so neither claim rests entirely on a platform that may skip.

---

## 10. Notes for the tech sheet

- Prefer the platform's real-path resolution primitive over hand-rolled segment walking; hand-rolled resolution is where traversal bugs live. But verify its behavior for nonexistent final components, since create operations legitimately target paths that do not yet exist — the parent must resolve and be contained even when the leaf does not exist.
- Containment must be a segment-aware comparison on resolved paths, never `startswith` on strings. This single mistake is the most common path-traversal bug in real gateways.
- Windows adds reparse points, 8.3 short names, alternate data streams, and device namespaces. Decide explicitly which are rejected outright versus resolved, and test on the platform the project actually develops on.
- Test 15 deserves as much attention as tests 1–14. The report publishes a false-positive rate, and this unit is where it comes from.
