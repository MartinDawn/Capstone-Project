# Evaluation Execution Guide

This document explains how to run the **conformance**, **sequential-cost**, **artifact**, and **load** experiments across the three baselines (`B0-C0`, `B1-C0`, `B1-C2`) on Docker containers. The experimental contract is [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md) (protocol **BP-20260922-v6**).

The experiments run **independently**. There is no combined campaign runner: each family has its own entry point and writes only into its own evidence root.

---

## 1. Prerequisites

- **Docker & Docker Desktop**: the daemon must be running.
- **Python 3.10+** on `PATH`. `pytest` is needed only to run the offline test suite.
- **Java JDK 17+**: needed for fixture generation and the independent oracle.

- **k6**: needed only for the load experiment (E-LOAD).

---

## 2. Runners

| Experiment | Runner | Evidence root |
|---|---|---|
| Conformance | `evaluation/bin/conformance/run_conformance.py` | `evaluation/evidence/conformance/` |
| Sequential authorization cost | `evaluation/bin/perf/run_cost.py` | `evaluation/evidence/cost/` |
| Artifact sizes and wire bytes | `evaluation/bin/artifacts/measure_artifacts.py` | `evaluation/evidence/artifacts/` |
| Offered load (E-LOAD) | `evaluation/bin/perf/run_perf.py` | `evaluation/evidence/perf/` |
| Analysis | `evaluation/analysis/analyze_cost.py` | `evaluation/results/<analysis-id>/` |

The measurement runners share this CLI shape:

```
--config <path>  --purpose {smoke|pilot|final}  [--campaign-id ID]
[--models B0-C0 B1-C0 B1-C2]  [--workloads Medium]  (--dry-run | --execute)
```

`run_cost.py` also takes `--batches N --attempts-per-batch N --warmup-attempts N --resume`. `measure_artifacts.py` takes `--samples N`.

### A. Conformance

```bash
python evaluation/bin/conformance/run_conformance.py \
  --config evaluation/configs/conformance-local.json \
  --purpose smoke --campaign-id smoke-conf-001 --execute
```

Conformance must pass for the exact evaluated source before any final cost evidence is accepted.

### B. Sequential authorization cost

```bash
python evaluation/bin/perf/run_cost.py \
  --config evaluation/configs/cost-vm.json \
  --purpose pilot --campaign-id pilot-cost-001 --execute
```

For each (workload, batch, model) window the runner:

1. stops all stacks and starts the model under test;
2. for B1, provisions a valid Root/Scope VC (F1), measured and reported separately;
3. runs the warm-up attempts (excluded from every metric);
4. runs the measured attempts one after another, each with a fresh session, cookies, challenge, and request identifier;
5. stops all stacks and seals the run package.

Profiles (batches, measured attempts per batch, warm-up attempts): smoke 1/2/1, pilot 1/5/2, final 5/10/2. Any value can be set on the command line or in the configuration `cost` block.

Only the authorization phase is measured, from the first authorization request to access-token issuance, on a monotonic clock. A failed attempt is recorded and is never replaced by a retry.

### C. Artifact sizes and wire bytes

```bash
python evaluation/bin/artifacts/measure_artifacts.py \
  --config evaluation/configs/cost-vm.json \
  --purpose pilot --campaign-id pilot-artifacts-001 --execute
```

Records the exact serialized size and SHA-256 of every observable authorization artifact (including the real Delegation VC for B1) and the application-level wire bytes of each named step. F1 is reported separately. Unobservable artifacts are `UNAVAILABLE` with a reason and are never estimated.

### D. Analysis

```bash
python evaluation/analysis/analyze_cost.py --campaign-id pilot-cost-001 pilot-artifacts-001 \
  --analysis-id diag-pilot-001 --allow-diagnostic
```

Evidence is selected by explicit campaign or run IDs. Smoke and pilot evidence needs `--allow-diagnostic` and is labelled diagnostic; it is refused in a final analysis.

### E. Offered load (E-LOAD)

```bash
python evaluation/bin/perf/session_isolation_live.py --configuration B1-C0
python evaluation/bin/perf/session_isolation_live.py --configuration B1-C2
python evaluation/bin/perf/run_perf.py --config evaluation/configs/perf-vm.json --purpose pilot --dry-run
```

The isolation proof must exist for the current source digest before any B1 pilot or final window. Rate levels come from `load.rates_tps` in the configuration or from `--rates`.

### Final execution

`--purpose final` fails closed unless the protocol manifest and the configuration are frozen and approved, the repository is committed (or the approved dirty-patch digest matches), and each model has a passing conformance run for the same source digest. `--dry-run` lists the remaining blockers:

```bash
python evaluation/bin/perf/run_cost.py --config evaluation/configs/final-cost-proposed.json --purpose final --dry-run
```

---

## 3. Dry-run inspection

```bash
python evaluation/bin/conformance/run_conformance.py --config evaluation/configs/conformance-local.json --purpose smoke --dry-run
python evaluation/bin/perf/run_cost.py               --config evaluation/configs/cost-local.json        --purpose smoke --dry-run
python evaluation/bin/artifacts/measure_artifacts.py      --config evaluation/configs/cost-local.json        --purpose smoke --dry-run
```

---

## 4. Standalone components

```bash
python evaluation/bin/conformance/conformance_v3.py --configuration B0-C0 --run-id run-b0-conf-01
python evaluation/bin/conformance/conformance_v3.py --configuration B1-C2 --run-id run-b1c2-conf-01 --include-quantum
python -m pytest -q evaluation/tests
```

For local containers, `run-conformance-local.ps1` sets the localhost endpoint overrides and calls `conformance_v3.py`.

---

## 5. Evidence output

```
evaluation/evidence/conformance/<campaign-id>/   campaign manifest, commands, handoff, logs
evaluation/evidence/conformance/<run-id>/        manifest.json, cases.jsonl, traces.jsonl, ...
evaluation/evidence/cost/<campaign-id>/          attempts.csv, batch-summary.csv, campaign-summary.csv, campaign-manifest.json, handoff.md, logs
evaluation/evidence/cost/<run-id>/               per window: manifest.json, attempts.csv, warmup-attempts.csv, f1.csv (B1), fingerprint.json
evaluation/evidence/artifacts/<campaign-id>/     campaign manifest, handoff, logs
evaluation/evidence/artifacts/<...>-artifacts-<w>-<m>/ artifact-measurements.csv, network-measurements.csv, manifest.json
evaluation/results/<analysis-id>/                analysis-manifest.json, *-summary.csv, paired-comparisons.csv, tables/*.tex, limitations.md
```

Run IDs, campaign IDs, and analysis IDs are immutable. `evaluation/evidence/perf-probe/` holds exploratory rate-ladder output and is diagnostic only.

---

## 6. Notes for running the stacks locally

- **Root `.env` points at the VMs.** It sets `BANK_HOST`, `KEYCLOAK_HOST`, `FRONTEND_BANK_HOST`, and `TPP_HOST` to the VM addresses, and both `docker compose` and the Python flows read it. For a local run, override every host in the shell (shell variables win over `.env`) or the wallet and gateways will call the VMs:
  `BANK_HOST=host.docker.internal TPP_HOST=host.docker.internal FRONTEND_BANK_HOST=localhost WALLET_HOST=localhost` for the compose command, and `BANK_HOST/KEYCLOAK_HOST/TPP_HOST/WALLET_HOST=localhost` for the runners.
- **Published ports are proxy ports only.** Bank `:8443` (and `:9443` for the users' classical-TLS ingress), TPP `:4443`, wallet `:3443`. The VDAM flows honour `VDAM_ISSUER_URL` (default `https://$BANK_HOST:9443`, used by F1), `VDAM_TPP_URL` (`https://$TPP_HOST:4443`) and `VDAM_WALLET_URL` (`https://$WALLET_HOST:3443`). The B1-C2 ports `:8443` and `:6443` present hybrid PQC certificates that standard clients (Python `ssl`) cannot negotiate, so the client never connects to them: it calls only the TPP (`:4443`) and wallet (`:3443`), and the PQC handshakes happen on the server-to-server hops.
- **No compose override is needed anymore.** Keycloak, the issuer and the resource server no longer publish ports.
- **B0 is driven through the TPP.** The client calls the B0 TPP (`B0_TPP_URL`, default `https://$TPP_HOST:4443`), which performs PAR and the token exchange itself. The client never holds the TPP certificate.
- **The first login of a fresh B0 realm must not overlap another.** Keycloak stores the user's consent on the first login, and two overlapping first logins can create duplicate consent rows (`More results found for user ... and client`); after that every login fails. The sequential runner never overlaps transactions, so the first login of a window is safe. To recover a damaged realm, remove the Postgres volume (`traditional-fapi_postgres_fapi_data`) and start again. On a fresh realm the first login is answered with a redirect to the consent screen, which the Python flow follows.
- **TPP state is per request.** `/api/request-delegate` returns a `requestId`, and `/api/token` reads it from the JSON body.
- **Delegation VC.** The Wallet's `approve-delegate` reply carries only the JTI. `measure_artifacts.py` reads the credential from the Wallet's existing `GET /api/delegate-vcs/{requestId}` after the measured flow.
