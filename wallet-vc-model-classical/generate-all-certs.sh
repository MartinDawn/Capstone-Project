#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BANK_CERTS="${SCRIPT_DIR}/bank/tls-proxy/certs"
WALLET_CERTS="${SCRIPT_DIR}/wallet/tls-proxy/certs"
TPP_CERTS="${SCRIPT_DIR}/tpp/tls-proxy/certs"
AUTH_CERTS="${SCRIPT_DIR}/bank/auth_server/certs"

mkdir -p "${BANK_CERTS}" "${WALLET_CERTS}" "${TPP_CERTS}" "${AUTH_CERTS}"

echo "============================================================"
echo "Generating Classical ECDSA P-384 Certificates"
echo "============================================================"

# 1. Root CA (ECDSA P-384)
echo ">> [1/6] Generating ECDSA P-384 Root CA..."
openssl ecparam -name secp384r1 -genkey -noout -out "${BANK_CERTS}/ca.key"
openssl req -x509 -new -key "${BANK_CERTS}/ca.key" -sha384 \
  -out "${BANK_CERTS}/ca.crt" \
  -subj "/CN=Classical ECDSA Root CA/O=BK Research/C=VN" -days 3650

# 2. Server Cert
echo ">> [2/6] Generating Server Certificate for tls-server-proxy..."
openssl ecparam -name secp384r1 -genkey -noout -out "${BANK_CERTS}/server.key"
openssl req -new -key "${BANK_CERTS}/server.key" -sha384 \
  -out "${BANK_CERTS}/server.csr" \
  -subj "/CN=tls-server-proxy/O=BK Research/C=VN"

cat > "${BANK_CERTS}/server-ext.cnf" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tls-server-proxy
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "${BANK_CERTS}/server.csr" \
  -CA "${BANK_CERTS}/ca.crt" -CAkey "${BANK_CERTS}/ca.key" \
  -CAcreateserial -out "${BANK_CERTS}/server.crt" -days 365 \
  -sha384 -extfile "${BANK_CERTS}/server-ext.cnf" -extensions v3_req

# 3. Wallet Client Cert
echo ">> [3/6] Generating Client Certificate for Wallet..."
openssl ecparam -name secp384r1 -genkey -noout -out "${BANK_CERTS}/wallet.key"
openssl req -new -key "${BANK_CERTS}/wallet.key" -sha384 \
  -out "${BANK_CERTS}/wallet.csr" \
  -subj "/CN=Classical Wallet Client/O=BK Research/C=VN"
openssl x509 -req -in "${BANK_CERTS}/wallet.csr" \
  -CA "${BANK_CERTS}/ca.crt" -CAkey "${BANK_CERTS}/ca.key" \
  -CAcreateserial -out "${BANK_CERTS}/wallet.crt" -days 365 -sha384

# 4. TPP Client Cert
echo ">> [4/6] Generating Client Certificate for TPP..."
openssl ecparam -name secp384r1 -genkey -noout -out "${BANK_CERTS}/tpp.key"
openssl req -new -key "${BANK_CERTS}/tpp.key" -sha384 \
  -out "${BANK_CERTS}/tpp.csr" \
  -subj "/CN=Classical TPP Client/O=BK Research/C=VN"
openssl x509 -req -in "${BANK_CERTS}/tpp.csr" \
  -CA "${BANK_CERTS}/ca.crt" -CAkey "${BANK_CERTS}/ca.key" \
  -CAcreateserial -out "${BANK_CERTS}/tpp.crt" -days 365 -sha384

# 5. Wallet Inbound Server Cert
echo ">> [5/6] Generating Server Certificate for tls-wallet-inbound..."
openssl ecparam -name secp384r1 -genkey -noout -out "${BANK_CERTS}/wallet-inbound.key"
openssl req -new -key "${BANK_CERTS}/wallet-inbound.key" -sha384 \
  -out "${BANK_CERTS}/wallet-inbound.csr" \
  -subj "/CN=tls-wallet-inbound/O=BK Research/C=VN"

cat > "${BANK_CERTS}/wallet-inbound-ext.cnf" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tls-wallet-inbound
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "${BANK_CERTS}/wallet-inbound.csr" \
  -CA "${BANK_CERTS}/ca.crt" -CAkey "${BANK_CERTS}/ca.key" \
  -CAcreateserial -out "${BANK_CERTS}/wallet-inbound.crt" -days 365 \
  -sha384 -extfile "${BANK_CERTS}/wallet-inbound-ext.cnf" -extensions v3_req

# 6. Browser Certs
echo ">> [6/6] Generating Browser HTTPS Certificate..."
openssl req -x509 -new -newkey rsa:2048 \
  -keyout "${BANK_CERTS}/browser.key" -out "${BANK_CERTS}/browser.crt" \
  -nodes -subj "/CN=localhost/O=BK Research/C=VN" -days 365

# Distribute certs
echo ">> Distributing certificates..."
cp "${BANK_CERTS}"/ca.crt "${WALLET_CERTS}/"
cp "${BANK_CERTS}"/wallet.crt "${WALLET_CERTS}/"
cp "${BANK_CERTS}"/wallet.key "${WALLET_CERTS}/"
cp "${BANK_CERTS}"/wallet-inbound.crt "${WALLET_CERTS}/"
cp "${BANK_CERTS}"/wallet-inbound.key "${WALLET_CERTS}/"
cp "${BANK_CERTS}"/browser.crt "${WALLET_CERTS}/"
cp "${BANK_CERTS}"/browser.key "${WALLET_CERTS}/"

cp "${BANK_CERTS}"/ca.crt "${TPP_CERTS}/"
cp "${BANK_CERTS}"/tpp.crt "${TPP_CERTS}/"
cp "${BANK_CERTS}"/tpp.key "${TPP_CERTS}/"
cp "${BANK_CERTS}"/browser.crt "${TPP_CERTS}/"
cp "${BANK_CERTS}"/browser.key "${TPP_CERTS}/"

cp "${BANK_CERTS}"/ca.crt "${AUTH_CERTS}/"
cp "${BANK_CERTS}"/server.crt "${AUTH_CERTS}/"
cp "${BANK_CERTS}"/server.key "${AUTH_CERTS}/"

echo "All Classical ECDSA certificates generated and distributed successfully!"
