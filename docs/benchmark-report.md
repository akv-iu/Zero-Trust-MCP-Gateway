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
| direct_ms | 900 | 6.881 | 9.672 | 15.329 | 3.684 | 32.416 |
| protected_ms | 900 | 61.300 | 92.301 | 125.051 | 36.026 | 146.694 |
| added_overhead_ms | 900 | 54.347 | 84.462 | 118.346 | 26.077 | 137.964 |
| stage: protocol+canonicalization | 900 | 0.728 | 1.379 | 2.174 | 0.498 | 10.111 |
| stage: policy | 900 | 1.865 | 3.432 | 4.398 | 1.296 | 12.936 |
| stage: upstream | 900 | 5.981 | 8.216 | 11.351 | 4.026 | 22.498 |
| stage: audit | 900 | 2.856 | 4.686 | 5.913 | 1.665 | 28.604 |

### modest-concurrency (concurrency 4)

| Distribution (ms) | n | p50 | p95 | p99 | min | max |
|---|---:|---:|---:|---:|---:|---:|
| direct_ms | 900 | 7.082 | 10.089 | 12.359 | 4.438 | 18.921 |
| protected_ms | 900 | 26.379 | 32.098 | 35.604 | 18.773 | 56.003 |
| added_overhead_ms | 900 | 19.092 | 25.486 | 28.331 | 8.464 | 49.418 |
| stage: protocol+canonicalization | 900 | 0.794 | 1.557 | 2.158 | 0.467 | 6.275 |
| stage: policy | 900 | 2.977 | 4.912 | 5.956 | 1.438 | 8.664 |
| stage: upstream | 900 | 9.150 | 14.204 | 16.797 | 4.952 | 21.758 |
| stage: audit | 900 | 6.665 | 9.843 | 11.672 | 3.152 | 21.541 |

## Audit completeness

Request events written / auditable requests issued: **113/113 (100.00%)**.

## Reproducibility environment

| Field | Value |
|---|---|
| commit sha | 31809ce1a9502fc29ec5fcccd72e1f1f890330aa (working tree dirty) |
| source fingerprint | cf174a7b389e4f05ac604093c38298a93c7ac28479903a04dc563f56e37f9ae7 |
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
| timestamp | 2026-08-10T23:00:31.683285+00:00 |
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
