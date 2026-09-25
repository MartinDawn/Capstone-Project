#!/bin/bash
# Generate self-signed certificates for Keycloak HTTPS (development only)
set -e

CERTS_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERTS_DIR"

echo "=== Generating self-signed certificates for development ==="

# Generate CA key and cert
openssl ecparam -name secp384r1 -genkey -noout -out "$CERTS_DIR/ca.key"
openssl req -x509 -new -nodes -key "$CERTS_DIR/ca.key" -sha384 -days 365 \
  -out "$CERTS_DIR/ca.crt" \
  -subj "/C=VN/ST=HCMC/L=HCMC/O=FAPI-Demo/OU=Dev/CN=FAPI-Demo-CA"

# Generate server key and CSR
openssl ecparam -name secp384r1 -genkey -noout -out "$CERTS_DIR/server.key"
openssl req -new -key "$CERTS_DIR/server.key" -sha384 \
  -out "$CERTS_DIR/server.csr" \
  -subj "/C=VN/ST=HCMC/L=HCMC/O=FAPI-Demo/OU=Dev/CN=localhost"

# Create server certificate signed by CA
cat > "$CERTS_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = keycloak
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "$CERTS_DIR/server.csr" \
  -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
  -out "$CERTS_DIR/server.crt" -days 365 -sha384 \
  -extfile "$CERTS_DIR/server.ext"

# Clean up temp files
rm -f "$CERTS_DIR/server.csr" "$CERTS_DIR/server.ext" "$CERTS_DIR/ca.srl"

echo ""
echo "=== Certificates generated successfully ==="
echo "  CA Certificate:     $CERTS_DIR/ca.crt"
echo "  Server Certificate: $CERTS_DIR/server.crt"
echo "  Server Key:         $CERTS_DIR/server.key"
echo ""
echo "NOTE: These are self-signed certificates for DEVELOPMENT ONLY."
