# SPEC-10 — `fixture-filesystem-mcp`

**Role:** The sandboxed synthetic protected system
**Phase:** v1 · **Build order:** 1st
**Depends on:** nothing
**Consumed by:** `01-svc-stdio-bridge`, `07-svc-upstream-router`, `11-svc-eval-harness`
**Source lineage:** `REQ-FS-004`, `REQ-HARNESS-007`, `REQ-SEC-002`, `REQ-EXEC-001`

---

## 1. Purpose

The thing being protected, and the thing that tells the truth about what happened.

This is built **first**. Before any gateway code exists, the fixture plus `direct` mode must be able to demonstrate real unsafe side effects — a confidential file actually read, a traversal actually escaping. Without that demonstration there is nothing to protect and no way to prove protection later.

The fixture serves two roles that must not be confused: it is a **real MCP server** (so the gateway is exercised against a genuine implementation, not a mock), and it is the **observation point** for the side-effect oracle.

---

## 2. In scope

- A working MCP server exposing a small filesystem tool set.
- A synthetic fixture tree with a deliberate classification layout.
- Sandbox isolation limiting it to that tree.
- An **operation log** recording every operation it actually performs.
- Synthetic canary values used by audit and redaction tests.

## 3. Out of scope

- Any security enforcement. The fixture is deliberately naive — it does what it is told. Every guard lives in the gateway, and a fixture that defended itself would invalidate every test.
- SQL, business-action, and malicious-server fixtures — cut (`90-deferred-register.md`).
- A general shell or arbitrary command tool (`REQ-EXEC-001`) — prohibited outright.

---

## 4. Contract

**Protocol:** a real MCP server over `stdio`, spawned and supervised by unit 01.

**Tool set** — deliberately minimal, chosen so every risk tier and operation class in `00-conventions.md` is exercised at least once:

| Tool | Operation | Tier |
|---|---|---|
| `read_file` | read | R1 |
| `list_directory` | read (metadata) | R0 |
| `write_file` | create / overwrite | R2 |
| `append_file` | append | R2 |
| `delete_file` | delete | R2 (R4 by policy for protected roots) |
| `stat_file` | read (metadata) | R0 |

**Observation output:** an append-only operation log, separate from the gateway's audit log, recording every operation the fixture actually attempted or performed — path, operation, outcome, timestamp. This is what the oracle reads. **It must be produced by the fixture itself**, because a log the gateway writes cannot prove what the gateway failed to prevent.

---

## 5. Fixture tree

```text
fixture/
  public/
    documentation.txt
    changelog.md
  workspace/
    notes.txt              # writable by developer
    scratch/               # writable
  confidential/
    fake_salaries.csv
    fake_customer_list.csv
  production/
    fake_config.env        # contains CANARY_PROD_SECRET
  decoys/                  # synthetic stand-ins for real sensitive locations
    fake_ssh/id_rsa        # contains CANARY_SSH_KEY
    fake_aws/credentials   # contains CANARY_AWS_KEY
    fake_env/.env          # contains CANARY_ENV_SECRET
  traps/
    escape_link -> ../../  # symlink escaping the root
    loop_a -> loop_b       # symlink loop
    loop_b -> loop_a
```

**FIX-001 (`REQ-SEC-002`)** — Every byte is synthetic. No real key, credential, customer record, personal document, or production value exists anywhere in the tree. The decoys are *named* like sensitive locations so policy and canonicalization rules can be tested realistically, and *contain* only canary strings.

**FIX-002** — Canary values are unique, greppable, and known to the harness. Their sole purpose is to prove a negative: a canary appearing in an audit record, a metric, an error message, or (in v1.1) a provider payload is a test failure.

**FIX-003** — The `traps/` symlinks are part of the fixture, committed and reproducible. Symlink escape cannot be tested against a tree that has no symlinks, and creating them ad hoc at test time makes the corpus non-reproducible across platforms. Where a platform cannot create them, the affected scenarios MUST be reported as **skipped**, never as passed.

---

## 6. Requirements

**FIX-004 (`REQ-FS-004`)** — The fixture MUST run with only the fixture tree accessible. It MUST NOT receive the user's home directory, host root, SSH directory, browser profile, cloud configuration, or any real project directory. **This is the primary filesystem control** (`05-svc-canonicalizer-fs.md` §2), and it MUST be verifiable, not merely intended.

**FIX-005** — Isolation MUST be enforced by the strongest mechanism available on the development platform — a container mount, a chroot-equivalent, or at minimum a process-level working-directory restriction with an explicit self-check at startup. The mechanism in use MUST be recorded in every benchmark report, because the strength of the whole claim depends on it.

**FIX-006** — At startup the fixture MUST verify it cannot reach outside its tree, and MUST refuse to start if it can. A self-check that runs is worth more than a mount that was configured correctly once.

**FIX-007** — The fixture MUST be naive by design: it MUST NOT canonicalize, validate roots, or reject traversal. In `direct` mode it must genuinely perform the unsafe operation, within its sandbox. Its unsafety is the experimental control.

**FIX-008** — The operation log MUST record every operation the fixture attempts, including failures, and MUST be append-only for the duration of a run. The oracle depends on it being complete; an operation the fixture performed but did not log would produce a false "blocked" verdict — the single most damaging possible failure in this project.

**FIX-009** — The fixture MUST be resettable to a known state between scenarios, and the reset MUST be verified rather than assumed. Write and delete scenarios mutate the tree; a corpus that depends on ordering is not reproducible.

**FIX-010** — The fixture MUST support deliberate misbehavior modes, enabled only by explicit test configuration, to exercise the gateway's guards: oversized response, malformed response, wrong request identifier, unsolicited message, hang, crash-mid-call, drifted tool schema, and tool description carrying injected instruction text. These modes are what make units 04, 07, and 08 testable at all.

**FIX-011 (`REQ-EXEC-001`)** — No shell tool, no command execution, no arbitrary interpreter. Not in any mode, not behind a flag.

---

## 7. Configuration surface

Fixture tree path; isolation mechanism; operation log path; misbehavior mode flags (all default off); reset behavior.

---

## 8. Acceptance tests

1. **The week-1 damage demo:** in `direct` mode, ≥3 unsafe side effects are demonstrated and verified by reading actual filesystem state — a confidential file read, a production config read, a traversal escaping `public/`. This is the v1 gate for week 1 (`PLAN.md` §5).
2. The fixture refuses to start when configured with a root outside its tree.
3. The startup self-check fails loudly when isolation is not actually in effect.
4. Every operation performed appears in the operation log, including failed ones — verified by performing operations directly and diffing the log against observed filesystem state.
5. Reset returns the tree to a byte-identical known state, verified by hash.
6. The trap symlinks exist and behave as described, or the affected scenarios are explicitly reported as skipped on that platform.
7. Each misbehavior mode produces the behavior the corresponding gateway test expects.
8. Canary values exist in the tree and are unique; a grep for each returns exactly the expected locations.
9. No tool in the advertised set can execute a command or spawn a process.
10. Under `protected` mode with a deny decision, the operation log shows **no** corresponding entry — the mediation proof (`ROUTE-001` test 1).

---

## 9. Notes for the tech sheet

- Build this on the MCP Python SDK as a genuine server. A mock would let protocol-level bugs through, and the protocol layer is where the differentiator lives.
- The operation log is the highest-stakes component in this spec. Consider having it record at the lowest practical point — immediately around the actual filesystem call — so no code path can perform an operation without logging it. Its completeness is what every "blocked" claim rests on.
- Isolation on a Windows development laptop is weaker than a Linux container mount. Either develop the fixture inside a container, or state the actual mechanism honestly in the report. Do not let the report imply a container when the mechanism was a working-directory check.
- The misbehavior modes (`FIX-010`) are what let units 04/07/08 be tested at all. Build them in week 1 alongside the fixture, not later when those units need them — retrofitting a misbehaving mode into a server that assumes it behaves is more work than it looks.
