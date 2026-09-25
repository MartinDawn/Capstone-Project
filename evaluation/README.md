# Experimental Evaluation Framework

This directory contains the technical evaluation framework for three implementations of the same Account Information Service task:

- `B0-C0`: Traditional FAPI 2.0 with RAR (`traditional-fapi`).
- `B1-C0`: VDAM with classical application signatures (`wallet-vc-model-classical`).
- `B1-C2`: VDAM with the configured hybrid profile (`wallet-vc-model`).

The protocol revision is `BP-20260922-v6`. It is specified in [docs/EVALUATION_PROTOCOL.md](../docs/EVALUATION_PROTOCOL.md) and, in machine-readable form, in `manifests/benchmark-protocol.json`. The workload is fixed to **Medium** for every experiment, so a full sweep is one measurement per model.

Final execution of E-COST and E-LOAD is guarded: it requires a passing conformance run for the exact evaluated source, a committed repository, and a frozen protocol digest. See "Final execution guard".

## Evaluation scope

The evaluation produces:

1. conformance evidence for the three configurations (unchanged, kept under its own protocol revision);
2. sequential, single-active-transaction authorization cost;
3. serialized artifact sizes;
4. application-level authorization wire bytes;
5. offered-load throughput/latency/error-rate at fixed offered-rate levels (E-LOAD);
6. deterministic analysis with generated tables and stated limitations.

**Not in scope:** maximum-throughput or saturation-point *claims* (E-LOAD reports observed metrics per offered-rate level, never an inferred capacity limit), production scalability claims, and CPU, RAM, storage, packet-level bandwidth, or network-capture measurements (the network metric stays application-level wire bytes, as defined in "Measurement boundary" below).

The comparisons are architecture cost (`B1-C0 - B0-C0`), hybrid migration cost (`B1-C2 - B1-C0`), and total observed change (`B1-C2 - B0-C0`), applied to both E-COST and E-LOAD metrics.

## Layout

```text
evaluation/
|-- README.md
|-- configs/               Campaign configurations (conformance, cost, perf; local and VM; frozen final)
|-- state/                 Generated run state (durability checkpoints)
|-- manifests/             Environment, profiles, protocol, cells, pairing, and workloads
|-- oracle/                Independent typed-authority reference implementation
|-- fixtures/              Deterministic workload and boundary fixtures
|-- tests/                 Conformance case definitions and offline unit tests
|-- bin/
|   |-- common/            constants, orchestrator, source_identity, cost_protocol, cost_stats, ais_flows, fingerprint
|   |-- conformance/       run_conformance.py, conformance_v3.py, conformance_runner.py
|   |-- artifacts/         measure_artifacts.py                         (artifact sizes and wire bytes)
|   `-- perf/              run_cost.py                                  (E-COST)
|                          run_perf.py, probe_saturation.py, k6/*.js   (E-LOAD)
|                          session_isolation_live.py                   (E-LOAD isolation-proof gate)
|-- evidence/
|   |-- conformance/       Immutable conformance campaign and run packages
|   |-- cost/              Immutable sequential-cost campaign and run packages
|   |-- artifacts/         Immutable artifact-size and wire-byte campaign and run packages
|   |-- perf/, perf-probe/ E-LOAD and probe evidence
|-- analysis/              analyze_cost.py
`-- results/               Derived tables and figures, one directory per analysis ID
```

`common/ais_flows.py` is the shared library of source-defined authorization flows (FAPI 2.0 + PKCE + PAR + mTLS for B0; VDAM F1 and F2--F4 for B1). The conformance runner, the sequential runner, and the artifact measurement all use it, so a measured attempt is the same lifecycle the conformance suite exercises.

### Measurement boundary

The client plays **only the user's side**: a browser, or the local app that talks to the wallet. Every server-to-server hop is performed by the real services and is part of the measured time.

| Baseline | Client calls | Done by the services |
|---|---|---|
| B0-C0 | TPP `/api/auth/initiate`, Keycloak login page (browser leg, no client certificate), TPP `/api/auth/token-exchange` | TPP performs PAR and the token exchange over mTLS |
| B1-C0, B1-C2 | TPP `request-delegate`, wallet `fetch-tpp-request` and `approve-delegate`, TPP `token` | Wallet submits the presentation to the TPP and calls the Bank; TPP calls the Bank for the challenge and the token |

Latency is measured from the first authorization request through access-token issuance, on a monotonic clock (`time.perf_counter_ns`). Wall-clock timestamps are provenance only. F1 (Root/Scope VC issuance) is measured once per batch and reported separately; it is never added to a repeated authorization. The resource server is not part of any measurement.

Wire bytes are named `application-level authorization wire bytes`. They are the request plus response bytes of each named client-facing step. TLS record overhead, retransmission, link-layer framing, and server-to-server traffic are outside the metric.

Client calls go through the proxies only (see the published-ports table below). The client runs on the **Client machine together with the wallet**, so it reaches the wallet on loopback and the TPP over the network; the TPP-to-Bank hop is always the real link between the two server VMs.

### Resource fairness

All three baselines use one resource table, `evaluation/manifests/resource-limits.json`: same role, same `cpus` and memory ceiling, and pinned image digests. Where the roles are comparable the runtime images are the same. The deliberate differences are recorded in the table: Keycloak 24.0.5 in B0 and 26.6.4 in B1, OQS nginx in B1-C2, and Node instead of Spring Boot for the B0 TPP. Because of these differences, the architecture-cost comparison includes implementation differences; only `B1-C2 - B1-C0` changes the cryptographic profile alone.

* `python evaluation/bin/common/fingerprint.py --audit` compares the compose files with the table.
* At every start the runner inspects the running containers, writes `fingerprints/<model>.json`, and stops the run on any mismatch. Each run package keeps a copy. It checks configuration only and never samples CPU or memory usage.

### Published ports (proxy-only)

Only proxies publish ports; every application port is internal to its Docker network.

| Baseline | Bank | TPP | Wallet |
|---|---|---|---|
| B0-C0 | `bank-gateway` `:8443` | `tpp-gateway` `:4443` (browser UI), `:6443` | none |
| B1-C0 | `tls-server-proxy` `:8443`, `:9443` (users, F1) | `tpp-gateway` `:4443` (users), `:6443` | `wallet-gateway` `:3443` |
| B1-C2 | `oqs-server-proxy` `:8443` (hybrid PQC), `:9443` (users, classical TLS, F1) | `tpp-gateway` `:4443` (users, classical TLS), `:6443` (PQC) | `wallet-gateway` `:3443` |

The B1-C2 `:8443` and `:6443` listeners present a hybrid `p384_mldsa65` certificate. Standard TLS clients cannot complete that handshake; only the OQS nginx gateways can. The client therefore calls the TPP (`:4443`) and wallet (`:3443`) over classical TLS (F1 reaches Keycloak through the Bank's classical `:9443`), and the PQC handshakes happen on the server-to-server hops.

## Sequential-cost campaigns

`run_cost.py` runs one (workload, batch, model) window at a time: stop every stack, start the model, provision the Root VC (B1 only, measured separately), run the warm-up attempts (excluded from every metric), run the measured attempts one after another, stop every stack. The model order of each paired block comes from `manifests/pairing-plan.json`.

| Purpose | Batches | Measured attempts per batch | Warm-up attempts per batch |
|---|---:|---:|---:|
| smoke | 1 | 2 | 1 |
| pilot | 1 | 5 | 2 |
| final | 5 | 10 | 2 |

Values come from the command line, then the configuration `cost` block, then the profile above. A final run refuses any override that changes the frozen values.

```powershell
# Describe every cell without starting services or writing evidence
python evaluation/bin/perf/run_cost.py --config evaluation/configs/cost-local.json --purpose smoke --dry-run
python evaluation/bin/perf/run_cost.py --config evaluation/configs/final-cost-proposed.json --purpose final --dry-run
python evaluation/bin/artifacts/measure_artifacts.py --config evaluation/configs/cost-local.json --purpose smoke --dry-run

# Live pilot on the VMs
python evaluation/bin/perf/run_cost.py --config evaluation/configs/cost-vm.json --purpose pilot --campaign-id pilot-cost-001 --execute
python evaluation/bin/artifacts/measure_artifacts.py --config evaluation/configs/cost-vm.json --purpose pilot --campaign-id pilot-artifacts-001 --execute

# Subset of models, more attempts (workload is fixed to Medium)
python evaluation/bin/perf/run_cost.py --config evaluation/configs/cost-vm.json --purpose pilot --models B1-C0 B1-C2 --attempts-per-batch 8 --campaign-id pilot-cost-002 --execute
```

Outputs under `evaluation/evidence/cost/<campaign-id>/`: `attempts.csv`, `batch-summary.csv`, `campaign-summary.csv`, `campaign-manifest.json`, `handoff.md`, `checksums.txt`, and logs. Each window is an immutable package `evaluation/evidence/cost/<run-id>/` with `manifest.json`, `attempts.csv` (measured), `warmup-attempts.csv`, `f1.csv` (B1), `fingerprint.json`, and `checksums.txt`. Run IDs and campaign IDs are immutable; reuse of an existing directory is rejected. A failed attempt stays in `attempts.csv` with its stage and reason and is never replaced.

### Artifact and wire-byte measurement

`measure_artifacts.py` runs the same flows once or `--samples N` times per (workload, model) (workload Medium) and records exact serialized sizes, SHA-256, and availability of every observable artifact, plus wire bytes for each named step and their total. For B1 the Delegation VC is the real credential, read from the Wallet's existing `GET /api/delegate-vcs/{requestId}` after the measured flow and outside the wire-byte accounting. A value that is only an identifier (a JTI) is rejected and reported `UNAVAILABLE`. The key-binding JWT is measured as the trailing component of the Delegation VC (its bytes are already inside the Delegation VC size, so the two rows are never added). `root_vc_presentation` is the Root VC as the Wallet presents it; it is the `authorization_vc` claim the TPP later embeds in its presentation, not the presentation itself. The Verifiable Presentation (`tpp_vp_assertion`) is signed by the TPP and posted to the Bank as the token-request `assertion`; no client-facing endpoint returns it, so it is `UNAVAILABLE` with the reason. Files contain sizes and digests only, never an artifact.

**Local-only diagnostic raw capture** ([protocol section 4.3](../docs/EVALUATION_PROTOCOL.md#43-local-only-diagnostic-capture-of-the-tpp-bank-hop)): `measure_artifacts.py --capture-local-network` (refused unless `configuration.environment == "local"`) additionally captures real on-the-wire bytes for the TPP<->Bank hop — the PAR request object (B0) and the F4 Verifiable Presentation assertion (B1), both server-to-server and otherwise `UNAVAILABLE` above — via a `nicolaka/netshoot` sidecar sharing the TPP gateway's and Bank gateway's own container network namespace (`evaluation/bin/common/packet_capture.py`). It reports byte/packet totals and a pcap SHA-256 per side in the manifest field `raw_packet_capture_local`, alongside (never merged into) `wire_bytes`. No TLS decryption; the `.pcap` stays local (`evaluation/evidence/` is gitignored) and is never committed.

### Analysis

```powershell
python evaluation/analysis/analyze_cost.py --campaign-id pilot-cost-001 pilot-artifacts-001 --analysis-id diag-pilot-001 --allow-diagnostic
python evaluation/analysis/analyze_cost.py --campaign-id final-cost-001 final-artifacts-001 --analysis-id final-a1
```

Evidence is always selected by explicit campaign or run IDs. Smoke and pilot evidence is refused unless `--allow-diagnostic` is given, the result is then labelled diagnostic, and it can never be mixed with final evidence. Output: `evaluation/results/<analysis-id>/` with `analysis-manifest.json`, `latency-summary.csv`, `f1-summary.csv`, `wire-summary.csv`, `artifact-summary.csv`, `paired-comparisons.csv`, `tables/*.tex`, `limitations.md`, and `checksums.txt`.

## Final execution guard

A final run (or artifact measurement) fails closed unless all of the following hold:

- `approval.state` is `frozen`, with a `decision_id`, and the protocol manifest `manifests/benchmark-protocol.json` is `frozen` with the same `frozen_digest`.
- `approval.frozen_digest` equals the digest computed from the current protocol manifest, configuration (without its approval block), pairing plan, and workload fixtures. Changing any of them after the approval invalidates it.
- The evaluation repository has a commit. The worktree is clean, or its dirty-patch digest equals `approval.allowed_dirty_patch_digest`.
- `approval.conformance_run_ids` names a completed, passing conformance run for each evaluated model, produced for the same source digest.

`--dry-run` of a final configuration lists the remaining blockers.

## Conformance

```powershell
python evaluation/bin/conformance/run_conformance.py --config evaluation/configs/conformance-local.json --purpose smoke --dry-run
python evaluation/bin/conformance/run_conformance.py --config evaluation/configs/conformance-local.json --purpose smoke --campaign-id smoke-conf-001 --execute
```

Conformance evidence is written under `evaluation/evidence/conformance/` and keeps protocol revision `BP-20260915-v3`. Conformance must precede any cost benchmark.

## Tests

```powershell
python -m pytest -q evaluation/tests
```

The suite is fully offline: no Docker, VM, or service is needed. It covers the sequential runner (profiles, precedence, deterministic ordering, one active transaction, warm-up exclusion, failure handling, immutable outputs, checksums, the final guard, a complete mocked smoke campaign), the artifact and wire-byte measurement, and the analysis on synthetic evidence with known values.

## Load campaigns (E-LOAD)

`bin/perf/run_perf.py` (per-rate protocol runner), `bin/perf/probe_saturation.py` (exploratory rate-ladder probe, never final evidence), and `bin/perf/k6/*.js` (open-loop `constant-arrival-rate` load scripts) implement E-LOAD: throughput, error rate, and latency at four offered-rate levels (1, 2, 4, and 8 TPS) for each of the three models, one workload (Medium; 12 cells).

```powershell
# Live isolation proof (required before any B1-C0/B1-C2 pilot or final window)
python evaluation/bin/perf/session_isolation_live.py --configuration B1-C0
python evaluation/bin/perf/session_isolation_live.py --configuration B1-C2

# Describe the schedule without starting services
python evaluation/bin/perf/run_perf.py --config evaluation/configs/perf-local.json --purpose pilot --dry-run

# Exploratory rate ladder (diagnostic only, never final evidence)
python evaluation/bin/perf/probe_saturation.py --config evaluation/configs/perf-local.json --rates 1 5 10 25 50 --dry-run
```

A window where k6 could not schedule the offered rate (`not_started > 0`) is disposed `GENERATOR_LIMITED` and is never read as server-capacity evidence. `probe_saturation.py` output is diagnostic only and is never pooled with protocol evidence.

## Evidence rules

- Reproduce the complete source-defined lifecycle; no endpoint shortcuts.
- Give each transaction an independent session, cookie, challenge, request, and replay state.
- Record failures without replacing them with successful retries.
- Use explicit run IDs and paired-block IDs in analysis; never select the latest file implicitly.
- Treat absent, not applicable, unsupported, not run, stopped, and unavailable as distinct states.
- Keep smoke and pilot evidence out of final estimates.
- Keep private keys, tokens, cookies, and personal data out of committed evidence.
