# VDAM: Verifiable Delegation Authorization for Open Banking

This repository contains the prototype implementations and the evaluation harness used to compare a
wallet-mediated, verifiable-credential delegation model (VDAM) with a traditional FAPI 2.0
authorization flow for the Open Banking Account Information Service (AIS), under both classical and
hybrid post-quantum cryptography.

## Baselines

| ID | Directory | Architecture | Application signatures | Transport |
|---|---|---|---|---|
| `B0-C0` | [`traditional-fapi/`](traditional-fapi/) | Three-party FAPI 2.0 (PAR, PKCE, mTLS, RAR) with Keycloak | PS256 | TLS / mTLS |
| `B1-C0` | [`wallet-vc-model-classical/`](wallet-vc-model-classical/) | Four-party VDAM (Wallet, TPP, Bank Issuer/DAS, Resource Server) | ECDSA P-256 (ES256) | TLS / mTLS |
| `B1-C2` | [`wallet-vc-model/`](wallet-vc-model/) | Four-party VDAM, same lifecycle as `B1-C0` | Composite ML-DSA-65 + ECDSA P-384 | OQS TLS (`X25519MLKEM768`) |

`B1-C0` and `B1-C2` share the same business lifecycle; the cryptographic profile is the comparison
variable. Architecture details, endpoints, and source maps for each baseline are in
[`docs/baselines/`](docs/baselines/README.md).

## Repository layout

```text
traditional-fapi/            B0-C0: Keycloak (FAPI 2.0 realm), TPP application, Resource Server, gateways
wallet-vc-model-classical/   B1-C0: Bank (Keycloak, Bank Issuer/DAS, Resource Server), TPP, Wallet
wallet-vc-model/             B1-C2: hybrid PQC variants of the B1 components, OQS gateways
evaluation/                  Conformance suite, independent oracle, cost/artifact/load runners, analysis
docs/                        Evaluation protocol, execution guide, deployment guide, baseline references
specs/openbanking-uk/        Open Banking UK OpenAPI specifications used as the API reference
tools/docker_stats_agent.py  Host-side `docker stats` endpoint for multi-VM runs
manage.sh, manage.ps1        Build, start, stop, and remove any baseline locally or per VM role
```

## Requirements

- Docker Engine with Docker Compose v2
- Python 3.10+ (`pip install pytest` for the offline test suite)
- Java 17 and Maven (only for building outside Docker)
- k6 (only for the load experiment)

## Quick start (single machine)

1. Copy the environment template and keep the localhost defaults:

   ```bash
   cp .env.example .env
   ```

2. Generate the TLS material. Private keys are not distributed; each baseline ships a script:

   ```bash
   (cd traditional-fapi && ./generate-certs.sh)
   (cd wallet-vc-model-classical && ./generate-all-certs.sh)
   ```

   For `B1-C2`, run `generate-certs.sh` in each of `wallet-vc-model/pqc-bank/oqs-proxy/`,
   `wallet-vc-model/pqc-tpp/oqs-proxy/`, and `wallet-vc-model/pqc-wallet/oqs-proxy/`, and
   `wallet-vc-model/pqc-bank/auth_server/scripts/gen-certs.sh`.

3. Build and start one baseline at a time:

   ```bash
   ./manage.sh local prepare b1-classical
   ./manage.sh local start   b1-classical
   ./manage.sh status
   ./manage.sh stop all
   ```

   Baseline names are `b0`, `b1-classical`, and `b1-pqc`. On Windows use `manage.ps1` with the same
   arguments.

For the two-VM topology used in the measurements (Bank VM, TPP/Wallet VM), see
[`docs/MULTI_VM_DEPLOYMENT_GUIDE.md`](docs/MULTI_VM_DEPLOYMENT_GUIDE.md).

## Evaluation

The experimental contract is [`docs/EVALUATION_PROTOCOL.md`](docs/EVALUATION_PROTOCOL.md) (protocol
`BP-20260922-v6`). Commands for every runner are in
[`docs/EXECUTION_GUIDE.md`](docs/EXECUTION_GUIDE.md) and [`evaluation/README.md`](evaluation/README.md).

| Experiment | Runner |
|---|---|
| Conformance (positive and negative cases, checked against an independent oracle) | `evaluation/bin/conformance/run_conformance.py` |
| E-COST: sequential authorization latency and wire bytes | `evaluation/bin/perf/run_cost.py` |
| E-ARTIFACT: serialized artifact sizes | `evaluation/bin/artifacts/measure_artifacts.py` |
| E-LOAD: offered-load throughput, latency, error rate | `evaluation/bin/perf/run_perf.py` |
| Analysis: paired-block bootstrap comparisons and LaTeX tables | `evaluation/analysis/analyze_cost.py` |

Offline tests (no Docker or network needed):

```bash
python -m pytest -q evaluation/tests
```

### Reproducing on your own machines

`evaluation/configs/*-vm.json` and `final-*-proposed.json` use documentation addresses
(`203.0.113.10` for the Bank VM, `203.0.113.20` for the TPP/Wallet VM). Replace them with your own
hosts. The `frozen_digest` in the final configurations was computed for the original deployment, so a
new deployment must pass conformance and be frozen again before `--purpose final` is accepted (see
section 6 of the protocol). Smoke and pilot runs need no freeze.

The measured environment was two 2-vCPU / 4 GiB Ubuntu 22.04 VMs running Docker; see
`evaluation/manifests/environment.json` and `evaluation/manifests/resource-limits.json`.

## Data

The Resource Servers serve account and transaction records from `berka.db`, an SQLite conversion of
the public PKDD'99 Czech financial dataset (Berka). Raw measurement evidence and analysis outputs are
not stored in this repository.

## Third-party material

- `wallet-vc-model/pqc-bank/mldsa-provider/` contains files derived from Keycloak (Apache License 2.0);
  they keep their original headers.
- `wallet-vc-model/pqc-bank/auth_server/patches/` contains a patched Keycloak `keycloak-services`
  JAR (Apache License 2.0).
- The `libs/` and `providers/` directories under `wallet-vc-model/` bundle Bouncy Castle
  `bcprov-jdk18on` 1.84 (Bouncy Castle License, MIT-style).
- `specs/openbanking-uk/` contains the Open Banking UK Read/Write API specifications, distributed
  under their own terms.

## License

Released under the MIT License (see [LICENSE](LICENSE)), except for the third-party material listed
above.

## Citation

If you use this software, please cite it as described in [CITATION.cff](CITATION.cff).
