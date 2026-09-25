# Keycloak FAPI 2.0 & OID4VCI Server

This directory contains the central components of the Bank, including:
1. **Keycloak**: Configured with FAPI 2.0 standard and custom plugin to accept PQC client certificates from Nginx (SPI).
2. **Postgres**: Database for Keycloak.
3. **PQC Signer (Sidecar)**: Java Spring Boot application providing an API for Node.js to sign JWT/SD-JWT using the ML-DSA-65 algorithm.
4. **Bank Issuer**: Node.js application issuing Verifiable Credentials.
5. **Resource Server**: Mock Bank API.

## Starting
Use `docker-compose up -d` in the root directory to start the entire system.
