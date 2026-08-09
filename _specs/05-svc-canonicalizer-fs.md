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
| Resolved path outside every approved root | `CANON_OUTSIDE_ROOT` |
| Symlink resolves outside an approved root | `CANON_SYMLINK_ESCAPE` |
| Symlink loop or resolution depth exceeded | `CANON_RESOLUTION_FAILED` |
| Resolution error (permission, unreadable component) | `CANON_RESOLUTION_FAILED` |
| Path is a sensitive decoy location | `CANON_SENSITIVE_PATH` |
| Operation class not derivable from the tool | `CANON_OPERATION_UNKNOWN` |
| Gateway config inside an approved root | startup fails |

---

## 8. Configuration surface

Approved roots with per-root read/create/overwrite/append/rename/delete permissions; decode rule version; max resolution depth; sensitive-decoy path list; classification map from fixture layout.

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

---

## 10. Notes for the tech sheet

- Prefer the platform's real-path resolution primitive over hand-rolled segment walking; hand-rolled resolution is where traversal bugs live. But verify its behavior for nonexistent final components, since create operations legitimately target paths that do not yet exist — the parent must resolve and be contained even when the leaf does not exist.
- Containment must be a segment-aware comparison on resolved paths, never `startswith` on strings. This single mistake is the most common path-traversal bug in real gateways.
- Windows adds reparse points, 8.3 short names, alternate data streams, and device namespaces. Decide explicitly which are rejected outright versus resolved, and test on the platform the project actually develops on.
- Test 15 deserves as much attention as tests 1–14. The report publishes a false-positive rate, and this unit is where it comes from.
