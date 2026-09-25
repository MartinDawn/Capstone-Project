# Multi-VM and Local Baseline Orchestration Guide

This document describes the unified container orchestration architecture for the VDAM research project. It explains how to operate in two distinct environments:
1. **Local Single-Host Mode**: Start an entire baseline (Bank + TPP + Wallet) using a single command.
2. **Multi-VM Evaluation Mode**: Host all Bank services on a dedicated Bank VM, all TPP services on a TPP VM, and Client/Wallet on a separate machine, running one research study at a time for noise-free benchmarking.

---

## 1. Architectural Role Mapping & Baselines

The evaluation benchmarks three distinct baselines:
- **`b0`**: Traditional Centralized FAPI 2.0 (`traditional-fapi`)
- **`b1-classical`**: VDAM Classical Baseline with ECDSA/ES384 (`wallet-vc-model-classical`)
- **`b1-pqc`**: VDAM Hybrid Classical + Post-Quantum with ML-DSA-65 (`wallet-vc-model`)

### Multi-VM Distribution Topology

```
┌────────────────────────────────────────────────────────┐
│                   Bank Server VM                       │
│              (e.g., IP: 192.168.1.10)                  │
├────────────────────────────────────────────────────────┤
│ Active based on current benchmark:                     │
│  • B0: postgres-fapi, keycloak-fapi, rs-fapi           │
│  • B1-Classical: postgres, keycloak, bank-issuer,      │
│                  resource-server, tls-server-proxy     │
│  • B1-PQC: postgres, keycloak, bank-issuer,            │
│            resource-server, oqs-server-proxy           │
└──────────────────────────▲─────────────────────────────┘
                           │
             Inbound mTLS  │  Port 8443 (Gateway), 9443 (user ingress, F1)
                           │  Application ports are internal only
                           │
┌──────────────────────────┴─────────────────────────────┐
│                    TPP Client VM                       │
│              (e.g., IP: 192.168.1.20)                  │
├────────────────────────────────────────────────────────┤
│ Active based on current benchmark:                     │
│  • B0: tpp-fapi, tpp-gateway (:4443)                   │
│  • B1-Classical: tpp-java, tpp-gateway (:4443, :6443)  │
│  • B1-PQC: pqc_tpp_java, tpp-gateway (:4443, :6443)    │
└────────────────────────────────────────────────────────┘
```

---

## 2. Master CLI Orchestrator (`manage.ps1` & `manage.sh`)

Use `manage.ps1` on Windows and `manage.sh` on Linux/VMs.

### Command Syntax

```bash
./manage.sh <role> prepare <baseline>   # build images, create containers (stopped)
./manage.sh <role> start   <baseline>   # start the prepared containers (never rebuilds)
./manage.sh <role> stop    <baseline>   # stop, keep the containers for the next start
./manage.sh <role> down    <baseline>   # remove containers and networks (volumes are kept)
./manage.sh stop [all | baseline]       # stop every container of a baseline
./manage.sh down [all | baseline]       # remove them
./manage.sh status
```

| Parameter | Supported Values |
| :--- | :--- |
| `<role>` | `local`, `bank`, `tpp`, `wallet` |
| `<baseline>` | `b0`, `b1-classical`, `b1-pqc` |

**Keep every baseline prepared but stopped.** Run `prepare` once per baseline on each machine. A stopped
container holds no ports, CPU or memory, so the three baselines (which share `8443`) can coexist; switching
baseline is then `stop all` plus `start`, with no build. `start` fails with a hint if the images are missing.

--- | :--- |
| `<role>` | `local`, `bank`, `tpp`, `wallet` |
| `<baseline>` | `b0`, `b1-classical`, `b1-pqc` |

---

## 3. Workflow A: Local Single-Host Development

Run all components of a baseline on a single machine for functional testing, UI validation, and development.

### Start a Baseline
```bash
# On Windows PowerShell:
.\manage.ps1 local start b0            # Starts Traditional FAPI
.\manage.ps1 local start b1-classical  # Starts Classical VDAM
.\manage.ps1 local start b1-pqc        # Starts PQC VDAM

# Or directly using Docker Compose:
cd wallet-vc-model && docker compose up -d
```

### Stop Containers
```bash
.\manage.ps1 stop all
```

---

## 4. Workflow B: Multi-VM Evaluation & Benchmarking

Machines: a **Bank VM**, a **TPP VM** and a **Client machine** that runs the wallet and the sequential
measurement runners. Run one baseline at a time.

### Step 1: Environment variables
Copy `.env.example` to `.env` on each machine and set the addresses of the Bank and TPP VMs
(`BANK_HOST`, `KEYCLOAK_HOST`, `FRONTEND_BANK_HOST`, `TPP_HOST`). `manage.sh` loads `.env`; on Windows the
runner passes the same variables through `command_environment` in the config.

### Step 2: Open the ports (cloud security group)
| VM | Ports | Used by |
| :--- | :--- | :--- |
| Bank | `8443` | proxy for TPP, wallet and B0 clients |
| Bank | `9443` | classical-TLS user ingress (F1 login, B1 baselines) |
| TPP | `4443`, `6443` | user ingress and the wallet-to-TPP hop |

Allowed sources: the two VMs and the client machine's public address.

### Step 3: Prepare every baseline once (stopped)
```bash
# Bank VM
./manage.sh bank prepare b0 && ./manage.sh bank prepare b1-classical && ./manage.sh bank prepare b1-pqc
# TPP VM
./manage.sh tpp prepare b0 && ./manage.sh tpp prepare b1-classical && ./manage.sh tpp prepare b1-pqc
# Client (PowerShell)
.\manage.ps1 wallet prepare b1-classical; .\manage.ps1 wallet prepare b1-pqc
```
Check with `docker ps` (empty) and `docker ps -a` (all `Created`).

### Step 4: Run a baseline
The runner starts and stops the baselines itself from `evaluation/configs/cost-vm.json`:
```bash
python evaluation/bin/perf/run_cost.py --config evaluation/configs/cost-vm.json --purpose smoke \
       --campaign-id smoke-vm-001 --models B0-C0 --execute
python evaluation/bin/artifacts/measure_artifacts.py --config evaluation/configs/cost-vm.json --purpose smoke \
       --campaign-id smoke-vm-artifacts-001 --models B0-C0 --execute
```
Manual equivalent for one baseline: `./manage.sh bank start b1-pqc` (Bank VM), `./manage.sh tpp start b1-pqc`
(TPP VM), `.\manage.ps1 wallet start b1-pqc` (client); afterwards `./manage.sh stop all` on each machine.

### Fairness check
`python evaluation/bin/common/fingerprint.py --audit` compares the compose files of the three baselines with
`evaluation/manifests/resource-limits.json`. Each start also writes `fingerprints/<model>.json` and stops the
run if a running container's limits or image digest differ from the table.

---

## 5. File Layout Summary

| Component | Local Master Compose | Bank VM Compose | TPP VM Compose | Wallet Compose |
| :--- | :--- | :--- | :--- | :--- |
| **B0** | `traditional-fapi/docker-compose.yml` | `traditional-fapi/docker-compose.bank.yml` | `traditional-fapi/docker-compose.tpp.yml` | *(N/A)* |
| **B1-C0** | `wallet-vc-model-classical/docker-compose.yml` | `wallet-vc-model-classical/bank/docker-compose.yml` | `wallet-vc-model-classical/tpp/docker-compose.yml` | `wallet-vc-model-classical/wallet/docker-compose.yml` |
| **B1-C2** | `wallet-vc-model/docker-compose.yml` | `wallet-vc-model/pqc-bank/docker-compose.yml` | `wallet-vc-model/pqc-tpp/docker-compose.yml` | `wallet-vc-model/pqc-wallet/docker-compose.yml` |
