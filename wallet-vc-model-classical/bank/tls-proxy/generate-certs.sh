#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
mkdir -p "${CERTS_DIR}"

echo "============================================================"
echo "Generating Classical ECDSA P-384 Certificates"
echo "============================================================"

# 1. Generate ECDSA P-384 Root CA
echo ">> [1/6] Generating ECDSA P-384 Root CA..."
openssl ecparam -name secp384r1 -genkey -noout -out "${CERTS_DIR}/ca.key"
openssl req -x509 -new -key "${CERTS_DIR}/ca.key" -sha384 \
  -out "${CERTS_DIR}/ca.crt" \
  -subj "/CN=Classical ECDSA Root CA/O=BK Research/C=VN" -days 3650

# 2. Generate Server Certificate for tls-server-proxy (ECDSA P-384)
echo ">> [2/6] Generating Server Certificate for tls-server-proxy..."
openssl ecparam -name secp384r1 -genkey -noout -out "${CERTS_DIR}/server.key"
openssl req -new -key "${CERTS_DIR}/server.key" -sha384 \
  -out "${CERTS_DIR}/server.csr" \
  -subj "/CN=tls-server-proxy/O=BK Research/C=VN"

# Create SAN extension for server cert
cat > "${CERTS_DIR}/server-ext.cnf" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tls-server-proxy
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "${CERTS_DIR}/server.csr" \
  -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial -out "${CERTS_DIR}/server.crt" -days 365 \
  -sha384 -extfile "${CERTS_DIR}/server-ext.cnf" -extensions v3_req

# 3. Generate Wallet Client Certificate (ECDSA P-384)
echo ">> [3/6] Generating Client Certificate for Wallet..."
openssl ecparam -name secp384r1 -genkey -noout -out "${CERTS_DIR}/wallet.key"
openssl req -new -key "${CERTS_DIR}/wallet.key" -sha384 \
  -out "${CERTS_DIR}/wallet.csr" \
  -subj "/CN=Classical Wallet Client/O=BK Research/C=VN"
openssl x509 -req -in "${CERTS_DIR}/wallet.csr" \
  -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial -out "${CERTS_DIR}/wallet.crt" -days 365 -sha384

# 4. Generate TPP Client Certificate (ECDSA P-384)
echo ">> [4/6] Generating Client Certificate for TPP..."
openssl ecparam -name secp384r1 -genkey -noout -out "${CERTS_DIR}/tpp.key"
openssl req -new -key "${CERTS_DIR}/tpp.key" -sha384 \
  -out "${CERTS_DIR}/tpp.csr" \
  -subj "/CN=Classical TPP Client/O=BK Research/C=VN"
openssl x509 -req -in "${CERTS_DIR}/tpp.csr" \
  -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial -out "${CERTS_DIR}/tpp.crt" -days 365 -sha384

# 5. Generate Wallet Inbound Server Certificate (ECDSA P-384)
echo ">> [5/6] Generating Server Certificate for tls-wallet-inbound..."
openssl ecparam -name secp384r1 -genkey -noout -out "${CERTS_DIR}/wallet-inbound.key"
openssl req -new -key "${CERTS_DIR}/wallet-inbound.key" -sha384 \
  -out "${CERTS_DIR}/wallet-inbound.csr" \
  -subj "/CN=tls-wallet-inbound/O=BK Research/C=VN"

cat > "${CERTS_DIR}/wallet-inbound-ext.cnf" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tls-wallet-inbound
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "${CERTS_DIR}/wallet-inbound.csr" \
  -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial -out "${CERTS_DIR}/wallet-inbound.crt" -days 365 \
  -sha384 -extfile "${CERTS_DIR}/wallet-inbound-ext.cnf" -extensions v3_req

# 6. Generate Browser HTTPS Certificate (RSA for browser compatibility)
echo ">> [6/6] Generating Browser HTTPS Certificate..."
openssl req -x509 -new -newkey rsa:2048 \
  -keyout "${CERTS_DIR}/browser.key" -out "${CERTS_DIR}/browser.crt" \
  -nodes -subj "/CN=localhost/O=BK Research/C=VN" -days 365

echo "============================================================"
echo "Classical ECDSA P-384 certificates generated in ${CERTS_DIR}:"
echo "============================================================"
ls -la "${CERTS_DIR}"
