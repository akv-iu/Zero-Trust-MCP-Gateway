# Zero-Trust MCP Gateway benchmark report

## Scoped security claim

Across 94 malicious scenarios in corpus version 0.1.0, the side-effect oracle observed 0 prohibited state changes or disclosures at the protected system.

## Security measurements

| Measure | Observed |
|---|---:|
| Malicious scenarios attempted | 94 |
| Malicious scenarios blocked with expected evidence | 94 |
| Prohibited side effects observed | 0 |
| Security enforcement rate (corpus 0.1.0) | 100.00% |
| CRITICAL outcomes | 0 |
| Indeterminate outcomes | 0 |
| Skipped hand-written scenarios | 3 |

## False-positive measurement

Legitimate scenarios allowed: 21/21. Observed false-positive rate: **0.00%**.

## Written and generated cases

Hand-written cases: **118**. Hypothesis-generated cases: **2500**, with **0** non-pass outcomes. Generated cases are not blended into the hand-written count.

## Paired overhead

Client, gateway, policy engine, fixture, and load generator ran on the same machine. These are co-located development measurements, not capacity claims.

### single-concurrency (concurrency 1)

| Distribution (ms) | n | p50 | p95 | p99 | min | max |
|---|---:|---:|---:|---:|---:|---:|
| direct_ms | 900 | 5.681 | 8.012 | 10.988 | 3.623 | 48.924 |
| protected_ms | 900 | 51.671 | 66.860 | 107.819 | 26.004 | 158.224 |
| added_overhead_ms | 900 | 45.646 | 62.097 | 102.071 | -11.232 | 147.254 |
| stage: protocol+canonicalization | 900 | 0.683 | 1.123 | 1.347 | 0.516 | 2.341 |
| stage: policy | 900 | 1.717 | 2.948 | 15.313 | 1.346 | 53.209 |
| stage: upstream | 900 | 4.976 | 6.953 | 10.162 | 3.844 | 22.028 |
| stage: audit | 900 | 2.411 | 3.110 | 4.275 | 1.662 | 13.756 |

### modest-concurrency (concurrency 4)

| Distribution (ms) | n | p50 | p95 | p99 | min | max |
|---|---:|---:|---:|---:|---:|---:|
| direct_ms | 900 | 5.804 | 7.641 | 9.255 | 4.044 | 12.554 |
| protected_ms | 900 | 21.637 | 24.765 | 26.945 | 15.662 | 29.906 |
| added_overhead_ms | 900 | 15.798 | 19.104 | 20.826 | 7.670 | 22.642 |
| stage: protocol+canonicalization | 900 | 0.629 | 1.166 | 1.378 | 0.489 | 1.694 |
| stage: policy | 900 | 2.422 | 3.560 | 4.293 | 1.183 | 6.694 |
| stage: upstream | 900 | 8.010 | 11.201 | 13.101 | 4.338 | 14.888 |
| stage: audit | 900 | 5.479 | 7.493 | 8.283 | 2.294 | 11.400 |

## Audit completeness

Request events written / auditable requests issued: **113/113 (100.00%)**.

## Reproducibility environment

| Field | Value |
|---|---|
| commit sha | 8ed364a4c34b1aba786c45978aca6c0e6f6590ce |
| source fingerprint | 55b361132884c9dedba6c96c561d990cca952e271246aa7890f88bc2c673a26b |
| policy revision | fdbb33454603aa73 |
| corpus version | 0.1.0 |
| audit schema version | 3 |
| hypothesis seed | 11011 |
| os | Windows-11-10.0.26200-SP0 |
| cpu | Intel64 Family 6 Model 170 Stepping 4, GenuineIntel |
| ram bytes | 16597598208 |
| python version | 3.13.7 (tags/v3.13.7:bcee1c3, Aug 14 2025, 14:15:11) [MSC v.1944 64 bit (AMD64)] |
| opa version | 1.19.0 |
| fixture isolation | weak |
| timestamp | 2026-08-11T02:42:01.390553+00:00 |
| case sensitive filesystem | False |
| durable audit writes | True |

## Limitations

- Filesystem canonicalization is defense in depth; this project does not claim TOCTOU safety.
- Fixture isolation for this run was `weak`; weak isolation is not a container boundary.
- 3 hand-written row(s) were skipped and are not counted as passes; Windows commonly lacks the symlink traps without Developer Mode.
- The client edge is loopback Streamable HTTP and the single upstream leg is stdio; this is not a multi-upstream or remote deployment result.
- The loopback edge authenticates no caller and uses locally configured, unverified identity (ADR-001 D-1 status).

## External contributions

No externally contributed failing case was recorded in this run. Additions retain their scenario id and fix history when one is received.
