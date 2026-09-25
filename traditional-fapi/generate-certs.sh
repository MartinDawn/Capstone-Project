#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
mkdir -p "${CERTS_DIR}"

OPENSSL_BIN="openssl"
if ! command -v openssl &> /dev/null; then
    if [ -f "/c/Program Files/Git/usr/bin/openssl.exe" ]; then
        OPENSSL_BIN="/c/Program Files/Git/usr/bin/openssl.exe"
    fi
fi

HOST_IP="${HOST_IP:-127.0.0.1}"
KEYCLOAK_HOST="${KEYCLOAK_HOST:-localhost}"
TPP_HOST="${TPP_HOST:-localhost}"
RS_HOST="${RS_HOST:-localhost}"

echo "============================================================"
echo "Generating TLS Certificates for Traditional FAPI Cluster"
echo "============================================================"

# 1. Root CA
echo ">> [1/4] Generating Traditional FAPI Root CA..."
"$OPENSSL_BIN" req -x509 -new -newkey rsa:2048 -keyout "${CERTS_DIR}/ca.key" -out "${CERTS_DIR}/ca.crt" -nodes -subj "/CN=Traditional FAPI Root CA/O=OpenBanking Research/C=VN" -days 3650

# 2. Keycloak Certificate
echo ">> [2/4] Generating Keycloak TLS Certificate..."
"$OPENSSL_BIN" req -new -newkey rsa:2048 -keyout "${CERTS_DIR}/keycloak.key" -out "${CERTS_DIR}/keycloak.csr" -nodes -subj "/CN=keycloak-fapi/O=OpenBanking Research/C=VN"
cat > "${CERTS_DIR}/keycloak-ext.cnf" << EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = keycloak-fapi
DNS.2 = localhost
DNS.3 = ${KEYCLOAK_HOST}
IP.1 = 127.0.0.1
IP.2 = ${HOST_IP}
EOF
"$OPENSSL_BIN" x509 -req -in "${CERTS_DIR}/keycloak.csr" -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial -out "${CERTS_DIR}/keycloak.crt" -days 365 -extfile "${CERTS_DIR}/keycloak-ext.cnf" -extensions v3_req
rm -f "${CERTS_DIR}/keycloak.csr" "${CERTS_DIR}/keycloak-ext.cnf"

# 3. TPP Certificate
echo ">> [3/4] Generating TPP Application TLS Certificate..."
"$OPENSSL_BIN" req -new -newkey rsa:2048 -keyout "${CERTS_DIR}/tpp.key" -out "${CERTS_DIR}/tpp.csr" -nodes -subj "/CN=tpp-fapi/O=OpenBanking Research/C=VN"
cat > "${CERTS_DIR}/tpp-ext.cnf" << EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tpp-fapi
DNS.2 = localhost
DNS.3 = ${TPP_HOST}
IP.1 = 127.0.0.1
IP.2 = ${HOST_IP}
EOF
"$OPENSSL_BIN" x509 -req -in "${CERTS_DIR}/tpp.csr" -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial -out "${CERTS_DIR}/tpp.crt" -days 365 -extfile "${CERTS_DIR}/tpp-ext.cnf" -extensions v3_req
rm -f "${CERTS_DIR}/tpp.csr" "${CERTS_DIR}/tpp-ext.cnf"

# 4. Resource Server Certificate
echo ">> [4/4] Generating Resource Server TLS Certificate..."
"$OPENSSL_BIN" req -new -newkey rsa:2048 -keyout "${CERTS_DIR}/rs.key" -out "${CERTS_DIR}/rs.csr" -nodes -subj "/CN=resource-server-fapi/O=OpenBanking Research/C=VN"
cat > "${CERTS_DIR}/rs-ext.cnf" << EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = resource-server-fapi
DNS.2 = localhost
DNS.3 = ${RS_HOST}
IP.1 = 127.0.0.1
IP.2 = ${HOST_IP}
EOF
"$OPENSSL_BIN" x509 -req -in "${CERTS_DIR}/rs.csr" -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial -out "${CERTS_DIR}/rs.crt" -days 365 -extfile "${CERTS_DIR}/rs-ext.cnf" -extensions v3_req
rm -f "${CERTS_DIR}/rs.csr" "${CERTS_DIR}/rs-ext.cnf"

# 5. Automatically Synchronize TPP Certificate Thumbprint to Keycloak Realm (AT-05)
if [ -f "${CERTS_DIR}/tpp.crt" ]; then
    THUMBPRINT=$("$OPENSSL_BIN" x509 -in "${CERTS_DIR}/tpp.crt" -outform DER | "$OPENSSL_BIN" dgst -sha256 -binary | "$OPENSSL_BIN" base64 -e | tr -d '=' | tr '/+' '_-')
    echo ">> Synchronizing TPP Certificate Thumbprint into Keycloak Realm: ${THUMBPRINT}"
    REALM_JSON="${SCRIPT_DIR}/auth-server/realm-config/traditional-fapi-realm.json"
    if [ -f "${REALM_JSON}" ]; then
        sed -i -E 's/\{\\"x5t#S256\\":\\"[^\\"]*\\"\}/{\\"x5t#S256\\":\\"'${THUMBPRINT}'\\"}/g' "${REALM_JSON}"
        echo "   Updated ${REALM_JSON} with new thumbprint."
    fi
fi

echo "============================================================"
echo "All TLS certificates generated and synchronized successfully!"
echo "============================================================"

