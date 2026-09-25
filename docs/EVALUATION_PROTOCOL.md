# Evaluation Protocol

Protocol revision: `BP-20260922-v6` (supersedes `BP-20260922-v5`).
Machine-readable form: `evaluation/manifests/benchmark-protocol.json`.

This document defines the experimental contract implemented by the harness under `evaluation/`.
Section numbers are stable and are cited from source comments and manifests.

## 1. Objective

The evaluation compares three implementations of the same Open Banking Account Information Service
(AIS) task:

| Configuration | Architecture | Application-signature profile | Directory |
|---|---|---|---|
| `B0-C0` | Traditional FAPI 2.0 (PAR, PKCE, mTLS, RAR) | classical | `traditional-fapi/` |
| `B1-C0` | VDAM (wallet and verifiable credentials) | classical ECDSA | `wallet-vc-model-classical/` |
| `B1-C2` | VDAM (wallet and verifiable credentials) | hybrid ECDSA + ML-DSA-65 | `wallet-vc-model/` |

The evidence package contains:

1. conformance evidence for all three configurations;
2. sequential, single-active-transaction authorization cost (E-COST);
3. serialized artifact sizes and application-level authorization wire bytes (E-ARTIFACT);
4. offered-load throughput, latency, and error rate at fixed offered-rate levels (E-LOAD); and
5. deterministic analysis producing tables and explicitly bounded conclusions.

The declared comparisons are:

- architecture cost: `B1-C0 - B0-C0`;
- hybrid migration cost: `B1-C2 - B1-C0`; and
- total observed change: `B1-C2 - B0-C0`.

`B0-C0` and the two `B1` configurations use different identity-provider versions and TPP
implementations (see `evaluation/manifests/resource-limits.json`). The architecture-cost comparison
therefore includes implementation differences; only `B1-C2 - B1-C0` isolates the change of
cryptographic profile.

## 2. Scope and non-goals

### 2.1 Scope

- Configurations: `B0-C0`, `B1-C0`, `B1-C2`.
- Workload: `Medium` (`evaluation/fixtures/data/workload_medium.json`). `Small` and `Large` fixtures
  remain on disk but are not part of the active protocol.
- E-COST concurrency: exactly one active business transaction per runner process.
- E-LOAD: open-loop offered rate, one k6 process per window, rate levels 1, 2, 4, and 8 TPS for every
  configuration.
- Primary latency boundary: first authorization request through access-token issuance.
- B1 F1 issuance (Root/Scope VC): measured and reported separately, never added to repeated
  authorizations or E-LOAD iterations.
- Evidence: immutable manifests, per-attempt observations, batch summaries, checksums, explicit
  exclusions, and explicit run selection.

### 2.2 Non-goals

- No maximum-throughput or saturation-point claim. E-LOAD reports throughput, latency, and error rate
  observed at each offered-rate level, not an inferred capacity limit.
- A generator-limited window (k6 could not schedule the offered rate) is never reported as evidence
  of server capacity.
- No production capacity, availability, or scalability claim.
- No CPU, RAM, storage, packet-level bandwidth, or full-network capture, except the local-only
  diagnostic in section 4.3.
- No claim that technical evidence establishes legal compliance or deployment readiness.

## 3. Experimental contract

### 3.1 Sequential authorization experiment (E-COST)

Runner: `evaluation/bin/perf/run_cost.py`.

```text
--config PATH
--purpose smoke|pilot|final
--campaign-id ID
--models B0-C0 B1-C0 B1-C2
--workloads Medium
--batches N
--attempts-per-batch N
--warmup-attempts N
--dry-run | --execute
```

| Purpose | Batches | Measured attempts per batch | Warm-up attempts per batch |
|---|---:|---:|---:|
| Smoke | 1 | 2 | 1 |
| Pilot | 1 | 5 | 2 |
| Final | 5 | 10 | 2 |

Within each paired block the model order follows the deterministic pairing plan
(`evaluation/manifests/pairing-plan.json`). Only one model stack is active at a time; all stacks are
stopped before and after each model window.

Every attempt uses a fresh session, cookie jar, challenge, request identifier, replay state, and
transaction identifier. A failed attempt is recorded and is never replaced by a successful retry.
Smoke, pilot, and final runs execute the same complete lifecycle; only the counts above differ.

### 3.2 Measurement modes

The final comparison uses `repeated_authorization`:

- `B0-C0`: the complete FAPI authorization path (PAR, browser authorization, token exchange) through
  token issuance.
- `B1-C0`, `B1-C2`: a valid Root/Scope VC is provisioned before the measured batch; F2--F4 are then
  executed through token issuance for every measured attempt.

F1 issuance is recorded once per measured batch: latency, application-level wire bytes, Root/Scope VC
serialized size, and outcome.

### 3.3 Per-attempt fields

`attempts.csv` contains at least:

```text
protocol_id,campaign_id,run_id,paired_block_id,batch,attempt,
configuration,workload,mode,transaction_id,start_timestamp,end_timestamp,
latency_ms,outcome,failure_stage,failure_reason,access_token_issued,
authorization_wire_bytes,source_digest,configuration_digest,fixture_digest
```

Latency uses a monotonic clock; wall-clock timestamps are provenance only. `batch-summary.csv` and
`campaign-summary.csv` report attempted/succeeded/failed counts; median, mean, standard deviation,
minimum, maximum, p95, and p99 latency; median and mean wire bytes; and the denominator of every rate.
Latency statistics are computed over successful attempts with the failure count shown beside them.

### 3.4 Load experiment (E-LOAD)

```text
evaluation/bin/perf/run_perf.py          per-rate protocol runner
evaluation/bin/perf/probe_saturation.py  exploratory rate ladder, never final evidence
evaluation/bin/perf/session_isolation_live.py
evaluation/bin/perf/k6/auth_load.js
evaluation/bin/perf/k6/probe_load.js
```

Offered-rate levels come from the configuration (`load.rates_tps`) or `--rates`. The final levels are
1, 2, 4, and 8 TPS for every configuration. `run_perf.py` writes one `perf-summary.csv` row per
(workload, model, rate level).

| Purpose | Batches per cell | Warm-up | Warm-up drain | Measurement | Drain | Cooldown |
|---|---:|---:|---:|---:|---:|---:|
| Smoke | 1 | 5 s | 5 s | 10 s | 5 s | 5 s |
| Pilot | 1 | 10 s | 10 s | 30 s | 10 s | 30 s |
| Final | 2 | 20 s | 10 s | 60 s | 20 s | 20 s |

Exact values live in `PROFILES` in `run_perf.py`.

**Restart granularity.** The stack is stopped and started once per (model, batch). All rate levels of
the campaign run consecutively within that lifetime; cooldown runs once at the end of the batch. The
bootstrap analysis resamples at the paired-block (batch) level, so rate levels sharing one stack
lifetime do not weaken the resampling unit. Fewer than five paired blocks is labelled `descriptive`.

**Generator-limited windows.** A window with `not_started > 0` is disposed `GENERATOR_LIMITED` and is
never pooled with `COMPLETED` windows.

**Isolation gate.** Before any pilot or final window for `B1-C0` or `B1-C2`, a live
two-overlapping-transaction isolation proof (`session_isolation_live.py --configuration <model>`) must
exist for the current source digest. `run_perf.py` enforces this in `ensure_isolation_proof()`. A
source change invalidates the proof.

## 4. Artifact and wire-byte measurement (E-ARTIFACT)

Runner: `evaluation/bin/artifacts/measure_artifacts.py`. Workload and model selection come from the
configuration or command line.

### 4.1 Artifacts

Where applicable, the complete serialized representation of:

- B0: PAR request URI or request object, authorization code, Access Token;
- B1: Root/Scope VC, Delegation VC, Authorization VP, key-binding material when separately
  serialized, Access Token;
- certificate or public-key material transmitted as part of a measured application artifact.

The Delegation VC is measured from the real credential, read from the Wallet's existing
`GET /api/delegate-vcs/{requestId}` endpoint after the measured flow. An identifier (JTI) is never
reported as a credential size. An artifact that is not observable without changing protocol behavior
is recorded as `availability=UNAVAILABLE` with a specific `missing_reason`.

### 4.2 Network measurement boundary

The metric is named *application-level authorization wire bytes*. It is the request plus response
bytes of named client-facing steps:

- B0: authorization initiation (PAR-facing), browser authorization, token exchange;
- B1: request delegation, fetch request, approve delegation, token exchange;
- F1: issuance steps, reported separately.

Per-step values and the boundary total are reported. Server-to-server traffic, TLS record overhead,
retransmission, and link-layer framing are outside the metric.

### 4.3 Local-only diagnostic capture of the TPP<->Bank hop

The metric of section 4.2 does not cover the TPP<->Bank hop: in B0 the PAR request object and the
token exchange are server-to-server, and in B1 the F4 Verifiable Presentation (`tpp_vp_assertion`) is
posted by the TPP directly to the Bank. Both are reported `UNAVAILABLE` in section 4.2 and are never
estimated.

A scoped diagnostic capture observes real on-the-wire totals for this hop:

- **Scope**: only when `configuration.environment == "local"`; never used against the VM deployment.
- **Mechanism**: `evaluation/bin/common/packet_capture.py` starts a `nicolaka/netshoot` sidecar in
  the network namespace of the TPP gateway and of the Bank gateway (`docker run --network
  container:<target> ... tcpdump ...`) for the measured window. The containers under test are not
  modified.
- **Output**: captured bytes (TCP/IP plus TLS ciphertext) and packet counts per side, and the pcap
  SHA-256. TLS is not decrypted and no payload is stored in any manifest. The `.pcap` stays under
  `evaluation/evidence/artifacts/<run-id>/pcap/` and is not committed.
- **Driver**: `measure_artifacts.py --capture-local-network`.
- **Never pooled**: `raw_packet_capture_local` is reported next to, not merged into, `wire_bytes`.
  The two numbers measure different boundaries.

## 5. Analysis

Entry point: `evaluation/analysis/analyze_cost.py`.

1. Evidence is selected by explicit campaign or run IDs; the newest directory is never selected
   implicitly.
2. Protocol, configuration, fixture, workload, unit, and paired-block compatibility are validated.
3. Smoke and pilot evidence is rejected from final aggregates (`--allow-diagnostic` produces a
   diagnostic-only analysis).
4. Failed, excluded, unavailable, and inconclusive dispositions are preserved.
5. Per-model descriptive statistics, and absolute and relative effects for the three comparisons.
6. 95% paired-block bootstrap intervals, seed `20260921`, 10,000 replicates.
7. A warning when the number of valid paired blocks is too small for a stable interval; p95/p99 are
   labelled descriptive for small samples.
8. CSV/JSON outputs and LaTeX tables generated directly from evidence.

Outputs under `evaluation/results/<analysis-id>/`: `analysis-manifest.json`, `latency-summary.csv`,
`f1-summary.csv`, `wire-summary.csv`, `artifact-summary.csv`, `paired-comparisons.csv`,
`tables/*.tex`, `limitations.md`, `checksums.txt`.

## 6. Source and build identity

Every run manifest records the repository commit and dirty-patch digest, the running container image
IDs by role, the configuration digest, the workload/fixture digest, the protocol digest, the
environment identifier, and a `source_digest` computed by
`evaluation/bin/common/source_identity.py` over the evaluated source files.

A final campaign fails closed unless:

- the protocol manifest and the configuration are `frozen` and carry the same `frozen_digest`;
- `approval.frozen_digest` equals the digest recomputed from the protocol manifest, the configuration
  (without its approval block), the pairing plan, and the workload fixtures;
- the worktree is clean, or its patch digest equals `approval.allowed_dirty_patch_digest`; and
- `approval.conformance_run_ids` names a passing conformance run for each configuration under the same
  source digest.

## 7. Tests

```bash
python -m pytest -q evaluation/tests
```

The suite is offline (no Docker, VM, or service). It covers the sequential runner (profiles,
precedence, deterministic ordering, one active transaction, warm-up exclusion, failure handling,
immutable outputs, checksums, the final guard, a complete mocked smoke campaign), artifact and
wire-byte accounting, and the analysis on synthetic evidence with known values.

## 8. Identifiers referenced in manifests

Configuration and manifest files refer to protocol changes and resolved issues by identifier.

| ID | Meaning |
|---|---|
| `DEC-013` | E-LOAD removed from scope under `BP-20260921-v4`. |
| `DEC-020` | E-LOAD reinstated under `BP-20260922-v5`. |
| `DEC-021` | E-LOAD stack restart granularity changed to once per (model, batch). |
| `DEC-022` | Local-only diagnostic capture of the TPP<->Bank hop (section 4.3). |
| `DEC-023` | Workload fixed to `Medium` for all experiments (`BP-20260922-v6`). |
| `DEC-025` | Final E-LOAD window profile (section 3.4). |
| `DEC-026` | Freeze of the E-COST final configuration. |
| `DEC-027` | Freeze of the E-LOAD final configuration. |
| `BLK-003` | Durable issuance-binding store for B1 (verified across restarts). |
| `BLK-004` | Live two-overlapping-transaction isolation proof for B1 (section 3.4); closed. |
| `BLK-013` | Defects in the E-LOAD rate-ladder tooling; fixed and verified by live execution. |
