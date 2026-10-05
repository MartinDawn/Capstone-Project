# Experimental environment and configuration — final-cost-vm-r936c55a-a1

This is a human-readable companion to `analysis-manifest.json`. Every value below is taken directly
from the campaign's own evidence (`fingerprint.json` per run, `campaign-manifest.json`,
`evaluation/manifests/workloads.json`, `evaluation/manifests/resource-limits.json`) or from
`docs/VM-INFO`, not retyped from memory. Run date: 2026-09-23 (campaign created at
2026-09-23T09:17:16Z, UTC).

## 1. Deployment topology

Three separate machines, each with an independently measured Docker daemon (`docker info`, captured
per run in `fingerprint.json`):

| Role | Machine | Location | vCPU | RAM (reported by Docker) | Docker | cgroup |
|---|---|---|---:|---:|---|---|
| Bank (B0's Keycloak/resource-server, B1's bank-issuer/wallet's Bank leg) | Alibaba ECS VM, `<bank-vm>` | Singapore | 2 | 3.41 GiB (3,664,932,864 B) | 29.7.2 | v2 |
| TPP | Alibaba ECS VM, `<tpp-vm>` | Tokyo | 2 | 3.41 GiB (3,664,920,576 B) | 29.7.2 | v2 |
| Client + Wallet (B1 only) + test driver | Windows PC (Docker Desktop) | local | 12 | 7.64 GiB (8,205,291,520 B) | 28.0.4 | v1 |

Both VMs are `ecs.e-c1m2.large` instances, Ubuntu 22.04 64-bit (per `docs/VM-INFO`). Bank and TPP are
never co-located; every measured request that crosses a role boundary is a real network hop between
these hosts, not a loopback call — except the Wallet, which runs on the client machine, so
Wallet-facing calls in B1 are effectively local while TPP- and Bank-facing calls are not.

**Network RTT** (client↔TPP ≈ 88 ms, client↔Bank ≈ 60 ms, TPP↔Bank ≈ 71 ms) was measured in an earlier
session against the same two VMs and is not re-measured by this campaign; it is reported here for
context on why absolute latencies are in the seconds range, not as a value this analysis computed.

## 2. Resource limits (fairness)

Same role → same `cpus`/`memory` ceiling across all three baselines, verified by
`python evaluation/bin/common/fingerprint.py --audit` immediately before this campaign
(`evaluation/manifests/resource-limits.json`):

| Role | cpus | memory | Notes |
|---|---:|---:|---|
| postgres | 1.0 | 256 MiB | all three baselines |
| keycloak (B0) | 1.5 | 1536 MiB | on B0's repeated-measurement hot path (login + token every attempt) |
| keycloak_login (B1) | 1.0 | 1024 MiB | B1 only; F1 login only, not on the repeated-measurement path |
| gateway (nginx / OQS-nginx) | 0.5 | 256 MiB | all gateways, all baselines |
| issuer (bank-issuer, B1 only) | 1.5 | 1536 MiB | B1's actual hot-path token/VP-verification service |
| tpp / wallet | 1.0 | 1024 MiB | all baselines |
| resource_server | 0.5 | 256 MiB | not on the measured path for any baseline |

The `keycloak`/`keycloak_login` and `issuer` split (Keycloak lowered, bank-issuer raised for B1) was a
deliberate fairness correction made earlier this session: it puts the heavier resource tier on
whichever component actually sits on the repeated-measurement critical path for each baseline, instead
of matching by service name alone. See `evaluation/manifests/resource-limits.json`'s
`by_design_differences` for the full rationale.

## 3. Software versions and pinned images (per role, from this campaign's own `fingerprint.json`)

| Role | B0-C0 | B1-C0 | B1-C2 |
|---|---|---|---|
| Identity provider | `keycloak:24.0.5@sha256:f8ade94c…` | `keycloak:26.6.4@sha256:0aae0de7…` | `keycloak:26.6.4@sha256:0aae0de7…` (patched keycloak-services jar) |
| Gateway (mTLS) | `nginx:alpine@sha256:62ff2089…` | `nginx:alpine@sha256:62ff2089…` | `openquantumsafe/nginx:latest@sha256:beb0d254…` (hybrid PQC) |
| TPP app | Node (`traditional-fapi-tpp-fapi`, local build) | Java/Spring (`tpp-tpp-java`, local build) | Java/Spring (`pqc-tpp-tpp-java`, local build) |
| Postgres | `postgres:15@sha256:dfbbb0ad…` | same | same |
| Bank issuer | n/a (Keycloak issues tokens directly) | Java/Spring (`bank-bank-issuer`, local build) | Java/Spring (`pqc-bank-bank-issuer`, local build) |
| Wallet | n/a | Java/Spring (`wallet-wallet`, local build) | Java/Spring (`pqc-wallet-wallet`, local build) |

Every third-party image is pinned by digest (`@sha256:…`); locally built application images are
built from the exact source tree identified in section 5 (no separate registry digest, since they are
never pushed anywhere).

## 4. Workload

`Medium` (the only workload in scope under decision DEC-023): 5 accounts, 4 permissions
(`ReadAccountsDetail`, `ReadBalances`, `ReadTransactionsCredits`, `ReadTransactionsDetail`), 90-day
transaction history, page size 25. Fixture: `evaluation/fixtures/data/workload_medium.json`,
`fixture_sha256 = 5ab7741a7c31144311a19828f2160b9cf8607fd8fe064be711948f89bb6aa863` (matches every run's
`fixture_digest` in this campaign).

## 5. Source and protocol identity

- Evaluation repository commit: `936c55a48685d781d49970498f31bebf4b63b2ae`, worktree clean
  (`worktree_dirty: false`) at the moment this campaign ran.
- `source_digest` (canonical tree hash over the evaluation harness and all three baselines' source,
  excluding generated evidence/results/config/manifest/state bookkeeping):
  `09db2dbfc49fb42288a4bb8214462a16773abe1698a267a82d43d5e5c1f9d64b`.
- `configuration_digest`: `e144efede093b6484b767f773e37c6913d039a4c0926f75982ab336582aca3c3`
  (`evaluation/configs/final-cost-proposed.json`).
- `protocol_digest`: `1395e6c46d844446698b9b32902d6a7784fb13291633b0492ce60d43503d0f44`
  (`evaluation/manifests/benchmark-protocol.json`).
- Protocol: `BP-20260922-v6`. Frozen and author-approved under decision `DEC-026` before this campaign
  ran (`evaluation/state/decisions.jsonl`).
- Conformance: `conf-final-r5097483` — B0-C0, B1-C0, B1-C2 all `gate_disposition: pass`,
  `state: COMPLETE`, recorded `source_digest` matching this campaign's, run immediately beforehand.

## 6. Measurement profile

`repeated_authorization` mode, exactly one active transaction at a time (`run_cost.py`'s
transaction lock), boundary = first authorization request through access-token issuance. 5 batches ×
(2 warm-up + 10 measured) attempts per model = 50 measured attempts per model, 150 total. Stack
stopped and restarted once per (model, batch) window; every attempt inside a window uses a fresh
session, cookies, challenge, request ID, and transaction ID. B1 F1 (Root/Scope VC issuance) is
provisioned once per batch and reported separately, never pooled into the repeated-authorization
latency above.
