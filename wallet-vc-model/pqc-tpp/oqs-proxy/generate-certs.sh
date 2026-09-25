#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
mkdir -p "${CERTS_DIR}"

echo "============================================================"
echo "Generating PQC Hybrid Certificates (p384_mldsa65) via OQS"
echo "============================================================"

# 1. Generate OQS Hybrid Root CA (p384_mldsa65)
echo ">> [1/5] Generating OQS Hybrid Root CA..."
docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl req -x509 -new -newkey p384_mldsa65 \
  -keyout /certs/ca.key -out /certs/ca.crt \
  -nodes -subj "/CN=OQS Hybrid PQC Root CA/O=BK Research/C=VN" -days 3650

# 2. Generate Server Certificate for oqs-server-proxy (p384_mldsa65)
echo ">> [2/5] Generating Server Certificate for oqs-server-proxy..."
docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl req -new -newkey p384_mldsa65 \
  -keyout /certs/server.key -out /certs/server.csr \
  -nodes -subj "/CN=oqs-server-proxy/O=BK Research/C=VN"

docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl x509 -req -in /certs/server.csr \
  -CA /certs/ca.crt -CAkey /certs/ca.key \
  -CAcreateserial -out /certs/server.crt -days 365

# 3. Generate Wallet Client Certificate (p384_mldsa65)
echo ">> [3/5] Generating Client Certificate for Wallet..."
docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl req -new -newkey p384_mldsa65 \
  -keyout /certs/wallet.key -out /certs/wallet.csr \
  -nodes -subj "/CN=Hybrid PQC Wallet Client/O=BK Research/C=VN"

docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl x509 -req -in /certs/wallet.csr \
  -CA /certs/ca.crt -CAkey /certs/ca.key \
  -CAcreateserial -out /certs/wallet.crt -days 365

# 4. Generate TPP Client Certificate (p384_mldsa65)
echo ">> [4/5] Generating Client Certificate for TPP..."
docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl req -new -newkey p384_mldsa65 \
  -keyout /certs/tpp.key -out /certs/tpp.csr \
  -nodes -subj "/CN=Hybrid PQC TPP Client/O=BK Research/C=VN"

docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl x509 -req -in /certs/tpp.csr \
  -CA /certs/ca.crt -CAkey /certs/ca.key \
  -CAcreateserial -out /certs/tpp.crt -days 365

# 5. Generate Wallet Inbound Server Certificate (p384_mldsa65)
echo ">> [5/5] Generating Server Certificate for oqs-wallet-inbound..."
docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl req -new -newkey p384_mldsa65 \
  -keyout /certs/wallet-inbound.key -out /certs/wallet-inbound.csr \
  -nodes -subj "/CN=oqs-wallet-inbound/O=BK Research/C=VN"

docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl x509 -req -in /certs/wallet-inbound.csr \
  -CA /certs/ca.crt -CAkey /certs/ca.key \
  -CAcreateserial -out /certs/wallet-inbound.crt -days 365

echo "============================================================"
echo "Generating Classical ECDSA Certificates for Browser Proxies"
echo "============================================================"
docker run --rm -v "${CERTS_DIR}:/certs" openquantumsafe/curl \
  openssl req -x509 -new -newkey rsa:2048 \
  -keyout /certs/browser.key -out /certs/browser.crt \
  -nodes -subj "/CN=localhost/O=BK Research/C=VN" -days 365

echo "Certificates generated successfully in ${CERTS_DIR}:"
ls -la "${CERTS_DIR}"
