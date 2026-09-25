# Post-Quantum Cryptography (PQC) - Bank Service & Auth Server

This repository contains the Banking and Identity Provider infrastructure for the Post-Quantum Cryptography Hybrid Verifiable Credential & FAPI 2.0 system.

## Components
- **Keycloak** (`:8080`): OIDC / FAPI 2.0 Authorization Server with custom PQC SPI provider (`pqc-nginx`)
- **Postgres**: Keycloak database
- **Bank Issuer** (`:7000`): Spring Boot OID4VCI Credential Issuer
- **Resource Server** (`:4000`): Node.js Banking API (Berka dataset)
- **OQS Server Proxy** (`:8443`): OpenQuantumSafe Nginx Reverse Proxy terminating PQC TLS 1.3 (`p384_mldsa65` / `X25519MLKEM768`)

## Quick Start

### 1. Build Custom SPI (if needed)
```bash
cd auth_server/pqc-x509-provider
mvn clean package
cp target/pqc-x509-provider-1.0-SNAPSHOT.jar ../providers/
```

### 2. Run with Docker Compose
```bash
docker compose up -d --build
```

### 3. Verify
- Keycloak: `http://localhost:8080` (admin/admin)
- Bank Issuer: `http://localhost:7000/.well-known/openid-credential-issuer`
- OQS mTLS Endpoint: `https://localhost:8443`
