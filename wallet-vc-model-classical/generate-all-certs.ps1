# ============================================================
# Generate Classical ECDSA P-384 Certificates via OpenSSL
# ============================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BankCerts = Join-Path $ScriptDir "bank\tls-proxy\certs"
$WalletCerts = Join-Path $ScriptDir "wallet\tls-proxy\certs"
$TppCerts = Join-Path $ScriptDir "tpp\tls-proxy\certs"
$AuthServerCerts = Join-Path $ScriptDir "bank\auth_server\certs"

# Find OpenSSL executable
$OpenSSLExe = "openssl"
if (-not (Get-Command "openssl" -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
        $OpenSSLExe = "C:\Program Files\Git\usr\bin\openssl.exe"
    }
}

New-Item -ItemType Directory -Force -Path $BankCerts | Out-Null
New-Item -ItemType Directory -Force -Path $WalletCerts | Out-Null
New-Item -ItemType Directory -Force -Path $TppCerts | Out-Null
New-Item -ItemType Directory -Force -Path $AuthServerCerts | Out-Null

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Generating Classical ECDSA P-384 Certificates (OpenSSL)" -ForegroundColor Cyan
Write-Host "Using OpenSSL from: $OpenSSLExe" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Root CA (ECDSA P-384)
Write-Host ">> [1/6] Generating ECDSA P-384 Root CA..." -ForegroundColor Yellow
& $OpenSSLExe ecparam -name secp384r1 -genkey -noout -out (Join-Path $BankCerts "ca.key")
& $OpenSSLExe req -x509 -new -key (Join-Path $BankCerts "ca.key") -sha384 -out (Join-Path $BankCerts "ca.crt") -subj "/CN=Classical ECDSA Root CA/O=BK Research/C=VN" -days 3650

# 2. Server Cert for tls-server-proxy
Write-Host ">> [2/6] Generating Server Certificate for tls-server-proxy..." -ForegroundColor Yellow
& $OpenSSLExe ecparam -name secp384r1 -genkey -noout -out (Join-Path $BankCerts "server.key")
& $OpenSSLExe req -new -key (Join-Path $BankCerts "server.key") -sha384 -out (Join-Path $BankCerts "server.csr") -subj "/CN=tls-server-proxy/O=BK Research/C=VN"

@"
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tls-server-proxy
DNS.2 = localhost
IP.1 = 127.0.0.1
"@ | Out-File -Encoding ASCII (Join-Path $BankCerts "server-ext.cnf")

& $OpenSSLExe x509 -req -in (Join-Path $BankCerts "server.csr") -CA (Join-Path $BankCerts "ca.crt") -CAkey (Join-Path $BankCerts "ca.key") -CAcreateserial -out (Join-Path $BankCerts "server.crt") -days 365 -sha384 -extfile (Join-Path $BankCerts "server-ext.cnf") -extensions v3_req
Remove-Item (Join-Path $BankCerts "server.csr"), (Join-Path $BankCerts "server-ext.cnf") -ErrorAction SilentlyContinue

# 3. Wallet Client Cert
Write-Host ">> [3/6] Generating Client Certificate for Wallet..." -ForegroundColor Yellow
& $OpenSSLExe ecparam -name secp384r1 -genkey -noout -out (Join-Path $BankCerts "wallet.key")
& $OpenSSLExe req -new -key (Join-Path $BankCerts "wallet.key") -sha384 -out (Join-Path $BankCerts "wallet.csr") -subj "/CN=Classical Wallet Client/O=BK Research/C=VN"
& $OpenSSLExe x509 -req -in (Join-Path $BankCerts "wallet.csr") -CA (Join-Path $BankCerts "ca.crt") -CAkey (Join-Path $BankCerts "ca.key") -CAcreateserial -out (Join-Path $BankCerts "wallet.crt") -days 365 -sha384
Remove-Item (Join-Path $BankCerts "wallet.csr") -ErrorAction SilentlyContinue

# 4. TPP Client Cert
Write-Host ">> [4/6] Generating Client Certificate for TPP..." -ForegroundColor Yellow
& $OpenSSLExe ecparam -name secp384r1 -genkey -noout -out (Join-Path $BankCerts "tpp.key")
& $OpenSSLExe req -new -key (Join-Path $BankCerts "tpp.key") -sha384 -out (Join-Path $BankCerts "tpp.csr") -subj "/CN=Classical TPP Client/O=BK Research/C=VN"
& $OpenSSLExe x509 -req -in (Join-Path $BankCerts "tpp.csr") -CA (Join-Path $BankCerts "ca.crt") -CAkey (Join-Path $BankCerts "ca.key") -CAcreateserial -out (Join-Path $BankCerts "tpp.crt") -days 365 -sha384
Remove-Item (Join-Path $BankCerts "tpp.csr") -ErrorAction SilentlyContinue

# 5. Wallet Inbound Server Cert
Write-Host ">> [5/6] Generating Server Certificate for tls-wallet-inbound..." -ForegroundColor Yellow
& $OpenSSLExe ecparam -name secp384r1 -genkey -noout -out (Join-Path $BankCerts "wallet-inbound.key")
& $OpenSSLExe req -new -key (Join-Path $BankCerts "wallet-inbound.key") -sha384 -out (Join-Path $BankCerts "wallet-inbound.csr") -subj "/CN=tls-wallet-inbound/O=BK Research/C=VN"

@"
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tls-wallet-inbound
DNS.2 = localhost
IP.1 = 127.0.0.1
"@ | Out-File -Encoding ASCII (Join-Path $BankCerts "wallet-inbound-ext.cnf")

& $OpenSSLExe x509 -req -in (Join-Path $BankCerts "wallet-inbound.csr") -CA (Join-Path $BankCerts "ca.crt") -CAkey (Join-Path $BankCerts "ca.key") -CAcreateserial -out (Join-Path $BankCerts "wallet-inbound.crt") -days 365 -sha384 -extfile (Join-Path $BankCerts "wallet-inbound-ext.cnf") -extensions v3_req
Remove-Item (Join-Path $BankCerts "wallet-inbound.csr"), (Join-Path $BankCerts "wallet-inbound-ext.cnf") -ErrorAction SilentlyContinue

# 6. Browser Certs (RSA 2048)
Write-Host ">> [6/6] Generating Browser HTTPS Certificate..." -ForegroundColor Yellow
& $OpenSSLExe req -x509 -new -newkey rsa:2048 -keyout (Join-Path $BankCerts "browser.key") -out (Join-Path $BankCerts "browser.crt") -nodes -subj "/CN=localhost/O=BK Research/C=VN" -days 365

# Distribute certs to wallet, tpp, auth-server
Write-Host ">> Distributing certificates to Wallet, TPP, and AuthServer..." -ForegroundColor Green
Copy-Item (Join-Path $BankCerts "ca.crt") "$WalletCerts\" -Force
Copy-Item (Join-Path $BankCerts "wallet.crt") "$WalletCerts\" -Force
Copy-Item (Join-Path $BankCerts "wallet.key") "$WalletCerts\" -Force
Copy-Item (Join-Path $BankCerts "wallet-inbound.crt") "$WalletCerts\" -Force
Copy-Item (Join-Path $BankCerts "wallet-inbound.key") "$WalletCerts\" -Force
Copy-Item (Join-Path $BankCerts "browser.crt") "$WalletCerts\" -Force
Copy-Item (Join-Path $BankCerts "browser.key") "$WalletCerts\" -Force

Copy-Item (Join-Path $BankCerts "ca.crt") "$TppCerts\" -Force
Copy-Item (Join-Path $BankCerts "tpp.crt") "$TppCerts\" -Force
Copy-Item (Join-Path $BankCerts "tpp.key") "$TppCerts\" -Force
Copy-Item (Join-Path $BankCerts "browser.crt") "$TppCerts\" -Force
Copy-Item (Join-Path $BankCerts "browser.key") "$TppCerts\" -Force

Copy-Item (Join-Path $BankCerts "ca.crt") "$AuthServerCerts\" -Force
Copy-Item (Join-Path $BankCerts "server.crt") "$AuthServerCerts\" -Force
Copy-Item (Join-Path $BankCerts "server.key") "$AuthServerCerts\" -Force

Write-Host "============================================================" -ForegroundColor Green
Write-Host "All Classical ECDSA certificates generated via OpenSSL successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
