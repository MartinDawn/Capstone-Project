# Post-Quantum Cryptography (PQC) - Wallet Service

This repository contains the Wallet microservice for the Post-Quantum Cryptography Hybrid Verifiable Credential & FAPI 2.0 system.

## Components
- **Wallet Java** (`:5000`): Spring Boot microservice implementing OpenID4VCI credential issuance client and PQC hybrid cryptographic operations (`p384_mldsa65`).
- **Wallet Proxy** (`:3443`): Standard HTTPS Nginx Proxy for browser compatibility.
- **OQS Wallet Outbound**: OpenQuantumSafe Nginx Proxy establishing outbound PQC mTLS connection to the Bank (`:8443`).
- **OQS Wallet Inbound** (`:5443`): OpenQuantumSafe Nginx Proxy receiving inbound PQC mTLS delegation requests from TPP.

## Configuration
Edit `.env` to set the IP addresses or hostnames:
- `BANK_HOST`: Host/IP of the Bank VM (defaults to `host.docker.internal` for local development)
- `WALLET_HOST`: Host/IP of this Wallet VM (defaults to `localhost`)
- `TPP_HOST`: Host/IP of the TPP VM (defaults to `host.docker.internal`)

## Quick Start
```bash
docker compose up -d --build
```

Access the Wallet UI at `https://localhost:3443` (or `https://<WALLET_IP>:3443`).
