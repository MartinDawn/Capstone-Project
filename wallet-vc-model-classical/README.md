# Classical Cryptography Baseline — Wallet-VC Model

This project is a decentralized **4-party authorization model (Wallet-VC Model)** built with an **identical architectural topology and protocol flow** to the Post-Quantum Cryptography model (`wallet-vc-model`), but replacing quantum-resistant algorithms with **standardized, robust Classical Cryptography (NIST P-256 ECDSA, ECDHE, AES-128/256-GCM)**.

Its primary purpose is to provide an exact **empirical baseline** to directly compare TLS handshake latency, certificate/token/VC payload sizes, cryptographic signing/verification throughput, and system resource consumption against the PQC model.

---

> **Published ports (proxy-only).** Only the proxies publish ports; the Keycloak (`:8080`), Bank Issuer
> (`:7000`), Resource Server (`:4000`), wallet (`:5000`) and TPP (`:6001`) ports below are internal to
> their Docker networks and are no longer reachable from the host. Use Bank `:8443` (machines) / `:9443` (users),
> TPP `:4443`, wallet `:3443`. Keycloak's admin console is not published; use `docker exec`
> or a temporary compose override. See `evaluation/README.md` (published-ports table).


## 1. Cryptographic Comparison: PQC vs. Classical

| Dimension | PQC Model (`wallet-vc-model`) | Classical Baseline (`wallet-vc-model-classical`) |
| :--- | :--- | :--- |
| **mTLS Channel** | `X25519MLKEM768` (Hybrid Post-Quantum KEM) | `ECDHE-ECDSA-AES128-GCM-SHA256` (NIST P-256) |
| **X.509 Digital Certificates** | Hybrid `p384_mldsa65` (ECDSA + ML-DSA-65) | `ECDSA P-256` (secp256r1) |
| **VC Signing (Bank Issuer)** | Hybrid `P384_MLDSA65` (ES384 + ML-DSA-65) | `ES256` (NIST P-256 ECDSA) |
| **VP Signing (Wallet / TPP)** | `ES384` / Hybrid | `ES256` (NIST P-256 ECDSA) |
| **Signature Format** | Custom Hybrid Binary Format `[ver][len][sig1][sig2]` | Standard JWS (RFC 7515) |
| **Cryptographic Library** | Standard Java SunEC + In-process PQC | Java Standard Security + Nimbus JOSE/JWT |
| **Reverse Proxy** | OpenQuantumSafe Nginx (`openquantumsafe/nginx`) | Standard Nginx (`nginx:alpine`) |
| **Keycloak SPI** | Custom ML-DSA X.509 Provider (`mldsa-provider`) | Native Keycloak Built-in X.509 Providers |

---

## 2. 4-Party Decentralized Architecture

```
       +-------------------------------------------------------------+
       |                     BANK INFRASTRUCTURE                     |
       |  +------------------+   +---------------+   +------------+  |
       |  | Keycloak (Auth)  |   |  Bank Issuer  |   |  Resource  |  |
       |  |     :8080        |   | (OID4VCI :7000)|  |Server :4000|  |
       |  +--------+---------+   +-------+-------+   +-----+------+  |
       |           |                     |                 |         |
       |           +----------+----------+                 |         |
       |                      | (L7 Routing)               |         |
       |             +--------+---------+                  |         |
       |             | TLS Server Proxy |<-----------------+         |
       |             | (ECDSA mTLS :8443)|                           |
       +-------------+--------^---------+----------------------------+
                              |
               ECDSA mTLS     | (OID4VCI Issue VC)
                              |
       +----------------------+--------------------+
       | WALLET INFRASTRUCTURE                     |
       |  +---------------------+                  |
       |  | TLS Outbound Proxy  |                  |
       |  |       :18443        |                  |
       |  +----------^----------+                  |
       |             |                             |
       |  +----------+----------+   +------------+ |
       |  |    Wallet Backend   |   | TLS Inbound| |
       |  |  (Spring Boot :5000)|<--| Proxy :5443| |
       |  +----------+----------+   +-----^------+ |
       |             |                    |        |
       |  +----------v----------+         |        |
       |  | Wallet Browser Proxy|         |        |
       |  |   (HTTPS :3443)     |         |        |
       +--+---------------------+---------+--------+
                                          |
                           ECDSA mTLS     | (OID4VP Submit VP)
                                          |
       +----------------------------------+--------+
       | TPP INFRASTRUCTURE                        |
       |  +---------------------+                  |
       |  | TLS Outbound Proxy  |                  |
       |  | (:19443 Bank,       |                  |
       |  |  :15443 Wallet)     |                  |
       |  +----------^----------+                  |
       |             |                             |
       |  +----------+----------+                  |
       |  |     TPP Backend     |                  |
       |  |  (Spring Boot :6001)|                  |
       |  +----------+----------+                  |
       |             |                             |
       |  +----------v----------+                  |
       |  |   TPP Browser Proxy |                  |
       |  |     (HTTPS :4443)   |                  |
       +--+---------------------+------------------+
```

---

## 3. Protocol Workflows

### Phase 1: Verifiable Credential Issuance (OID4VCI)
1. **Wallet** initiates Pushed Authorization Request (PAR) to **Keycloak** over ECDSA mTLS.
2. User authenticates on Keycloak and grants account entitlements.
3. Wallet exchanges Authorization Code for Access Token.
4. Wallet signs proof JWT (`ES384`) and submits credential request to **Bank Issuer** (`POST /credential`).
5. Bank Issuer issues SD-JWT Verifiable Credential (`IdentityCredential` or `AuthorizationCredential`).

### Phase 2: Presentation & Data Delegation (OID4VP + Delegation)
1. **TPP** sends delegation request (`POST /api/request-delegate`) to Wallet.
2. User approves data access scopes on Wallet UI.
3. Wallet signs **Delegation VC** (`DelegatedAuthorizationCredential`) bound to TPP's client certificate thumbprint.
4. Wallet transmits Verifiable Presentation (VP) containing SD-JWT VC + Delegation VC to TPP.
5. TPP packages VP and submits to Bank Issuer (`POST /token`) via `urn:ietf:params:oauth:grant-type:jwt-bearer`.
6. Bank Issuer executes **6-step fail-closed verification pipeline**, computes scope intersection ($S_{token} = S_{SC} \cap S_H \cap S_R \cap S_T \cap S_P$), and issues Access Token.
7. TPP uses Access Token to invoke Banking Resource Server (`GET /api/accounts`, `/api/transfers`, etc.).

---

## 4. Deployment Instructions

### Step 1: Generate ECDSA P-384 Certificates
```powershell
# PowerShell
powershell -ExecutionPolicy Bypass -File generate-all-certs.ps1

# Or Bash
bash generate-all-certs.sh
```

### Step 2: Start Bank Cluster
```bash
cd bank
docker compose up -d --build
```

### Step 3: Start Wallet Cluster
```bash
cd ../wallet
docker compose up -d --build
```

### Step 4: Start TPP Cluster
```bash
cd ../tpp
docker compose up -d --build
```

### Or Start All Clusters via Helper Script:
```powershell
.\start-all.ps1
```

---

## 5. Service Endpoints

- **Wallet UI**: `https://localhost:3443` (or `http://localhost:5000`)
- **TPP UI**: `https://localhost:4443` (or `http://localhost:6001`)
- **Keycloak Admin Console**: `http://localhost:8080` (admin / admin)
- **Bank Issuer Health**: `http://localhost:7000/health`
- **Resource Server Health**: `http://localhost:4000/health`
