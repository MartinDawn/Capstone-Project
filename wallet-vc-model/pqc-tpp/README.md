# Post-Quantum Cryptography (PQC) - Third Party Provider (TPP) Service

This repository contains the Third Party Provider (TPP) microservice for the Post-Quantum Cryptography Hybrid Verifiable Credential & FAPI 2.0 system.

## Components
- **TPP Java** (`:6001`): Spring Boot microservice requesting delegation credentials and verifying Verifiable Presentations over PQC hybrid algorithms (`p384_mldsa65`).
- **TPP Proxy** (`:4443`): Standard HTTPS Nginx Proxy for browser compatibility.
- **OQS TPP Outbound**: OpenQuantumSafe Nginx Proxy establishing outbound PQC mTLS connections to:
  - Port `19443` -> Bank (`:8443`)
  - Port `15443` -> Wallet (`:5443`)

## Configuration
Edit `.env` to set the IP addresses or hostnames:
- `BANK_HOST`: Host/IP of the Bank VM (defaults to `host.docker.internal` for local development)
- `WALLET_HOST`: Host/IP of the Wallet VM (defaults to `host.docker.internal` for local development)

## Quick Start
```bash
docker compose up -d --build
```

Access the TPP UI at `https://localhost:4443` (or `https://<TPP_IP>:4443`).
