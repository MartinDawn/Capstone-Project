# Generate self-signed certificates for Keycloak HTTPS (development only)
# PowerShell version for Windows

$ErrorActionPreference = "Stop"

$CERTS_DIR = Join-Path (Split-Path $PSScriptRoot) "certs"
New-Item -ItemType Directory -Force -Path $CERTS_DIR | Out-Null

Write-Host "=== Generating self-signed certificates for development ===" -ForegroundColor Cyan

# Generate CA key and cert
openssl ecparam -name secp384r1 -genkey -noout -out "$CERTS_DIR\ca.key"
openssl req -x509 -new -nodes -key "$CERTS_DIR\ca.key" -sha384 -days 365 `
  -out "$CERTS_DIR\ca.crt" `
  -subj "/C=VN/ST=HCMC/L=HCMC/O=FAPI-Demo/OU=Dev/CN=FAPI-Demo-CA"

# Generate server key and CSR
openssl ecparam -name secp384r1 -genkey -noout -out "$CERTS_DIR\server.key"
openssl req -new -key "$CERTS_DIR\server.key" -sha384 `
  -out "$CERTS_DIR\server.csr" `
  -subj "/C=VN/ST=HCMC/L=HCMC/O=FAPI-Demo/OU=Dev/CN=localhost"

# Create SAN extension config
$extContent = @"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = keycloak
IP.1 = 127.0.0.1
"@
$extContent | Out-File -FilePath "$CERTS_DIR\server.ext" -Encoding ascii

# Create server certificate signed by CA
openssl x509 -req -in "$CERTS_DIR\server.csr" `
  -CA "$CERTS_DIR\ca.crt" -CAkey "$CERTS_DIR\ca.key" -CAcreateserial `
  -out "$CERTS_DIR\server.crt" -days 365 -sha384 `
  -extfile "$CERTS_DIR\server.ext"

# Clean up temp files
Remove-Item -Force -ErrorAction SilentlyContinue "$CERTS_DIR\server.csr", "$CERTS_DIR\server.ext", "$CERTS_DIR\ca.srl"

Write-Host ""
Write-Host "=== Certificates generated successfully ===" -ForegroundColor Green
Write-Host "  CA Certificate:     $CERTS_DIR\ca.crt"
Write-Host "  Server Certificate: $CERTS_DIR\server.crt"
Write-Host "  Server Key:         $CERTS_DIR\server.key"
Write-Host ""
Write-Host "NOTE: These are self-signed certificates for DEVELOPMENT ONLY." -ForegroundColor Yellow
