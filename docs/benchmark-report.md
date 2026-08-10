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
| direct_ms | 900 | 6.702 | 9.024 | 10.138 | 4.145 | 13.931 |
| protected_ms | 900 | 60.819 | 82.394 | 125.824 | 33.755 | 165.035 |
| added_overhead_ms | 900 | 54.457 | 75.404 | 119.292 | 28.037 | 160.160 |
| stage: protocol+canonicalization | 900 | 0.786 | 1.261 | 1.509 | 0.570 | 2.293 |
| stage: policy | 900 | 2.017 | 2.999 | 4.447 | 1.479 | 8.707 |
| stage: upstream | 900 | 6.069 | 7.913 | 9.491 | 4.383 | 12.577 |
| stage: audit | 900 | 2.770 | 4.498 | 5.039 | 1.871 | 9.855 |

### modest-concurrency (concurrency 4)

| Distribution (ms) | n | p50 | p95 | p99 | min | max |
|---|---:|---:|---:|---:|---:|---:|
| direct_ms | 900 | 7.794 | 11.265 | 13.316 | 5.160 | 16.595 |
| protected_ms | 900 | 29.737 | 35.043 | 39.283 | 23.227 | 42.947 |
| added_overhead_ms | 900 | 21.964 | 27.375 | 31.779 | 9.321 | 35.890 |
| stage: protocol+canonicalization | 900 | 0.840 | 1.656 | 2.026 | 0.596 | 2.905 |
| stage: policy | 900 | 3.420 | 5.243 | 7.335 | 1.794 | 11.189 |
| stage: upstream | 900 | 10.500 | 15.846 | 19.836 | 5.445 | 21.953 |
| stage: audit | 900 | 7.702 | 11.311 | 13.250 | 2.740 | 16.930 |

## Audit completeness

Request events written / auditable requests issued: **113/113 (100.00%)**.

## Reproducibility environment

| Field | Value |
|---|---|
| commit sha | 4ece91660d8c9f354b07dba6f929ebf584c3729a (working tree dirty) |
| source fingerprint | 576a5012e2121b818be8a313f403b5c0c7ee372d8be657876efb35f5fd2848f7 |
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
| timestamp | 2026-08-10T20:59:56.079401+00:00 |
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
