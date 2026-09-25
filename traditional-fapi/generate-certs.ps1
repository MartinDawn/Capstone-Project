# ============================================================
# Generate TLS Certificates for Traditional FAPI 2.0 Cluster
# ============================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir = Join-Path $ScriptDir "certs"
New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

# Find OpenSSL executable
$OpenSSLExe = "openssl"
if (-not (Get-Command "openssl" -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
        $OpenSSLExe = "C:\Program Files\Git\usr\bin\openssl.exe"
    }
}

$HostIp = if ($env:HOST_IP) { $env:HOST_IP } else { "127.0.0.1" }
$KeycloakHost = if ($env:KEYCLOAK_HOST) { $env:KEYCLOAK_HOST } else { "localhost" }
$TppHost = if ($env:TPP_HOST) { $env:TPP_HOST } else { "localhost" }
$RsHost = if ($env:RS_HOST) { $env:RS_HOST } else { "localhost" }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Generating TLS Certificates for Traditional FAPI Cluster" -ForegroundColor Cyan
Write-Host "Using OpenSSL from: $OpenSSLExe" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Root CA
Write-Host ">> [1/4] Generating Traditional FAPI Root CA..." -ForegroundColor Yellow
& $OpenSSLExe req -x509 -new -newkey rsa:2048 -keyout (Join-Path $CertsDir "ca.key") -out (Join-Path $CertsDir "ca.crt") -nodes -subj "/CN=Traditional FAPI Root CA/O=OpenBanking Research/C=VN" -days 3650

# 2. Keycloak Certificate
Write-Host ">> [2/4] Generating Keycloak TLS Certificate..." -ForegroundColor Yellow
& $OpenSSLExe req -new -newkey rsa:2048 -keyout (Join-Path $CertsDir "keycloak.key") -out (Join-Path $CertsDir "keycloak.csr") -nodes -subj "/CN=keycloak-fapi/O=OpenBanking Research/C=VN"

@"
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = keycloak-fapi
DNS.2 = localhost
DNS.3 = $KeycloakHost
IP.1 = 127.0.0.1
IP.2 = $HostIp
"@ | Out-File -Encoding ASCII (Join-Path $CertsDir "keycloak-ext.cnf")

& $OpenSSLExe x509 -req -in (Join-Path $CertsDir "keycloak.csr") -CA (Join-Path $CertsDir "ca.crt") -CAkey (Join-Path $CertsDir "ca.key") -CAcreateserial -out (Join-Path $CertsDir "keycloak.crt") -days 365 -extfile (Join-Path $CertsDir "keycloak-ext.cnf") -extensions v3_req
Remove-Item (Join-Path $CertsDir "keycloak.csr"), (Join-Path $CertsDir "keycloak-ext.cnf") -ErrorAction SilentlyContinue

# 3. TPP Application Certificate
Write-Host ">> [3/4] Generating TPP Application TLS Certificate..." -ForegroundColor Yellow
& $OpenSSLExe req -new -newkey rsa:2048 -keyout (Join-Path $CertsDir "tpp.key") -out (Join-Path $CertsDir "tpp.csr") -nodes -subj "/CN=tpp-fapi/O=OpenBanking Research/C=VN"

@"
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = tpp-fapi
DNS.2 = localhost
DNS.3 = $TppHost
IP.1 = 127.0.0.1
IP.2 = $HostIp
"@ | Out-File -Encoding ASCII (Join-Path $CertsDir "tpp-ext.cnf")

& $OpenSSLExe x509 -req -in (Join-Path $CertsDir "tpp.csr") -CA (Join-Path $CertsDir "ca.crt") -CAkey (Join-Path $CertsDir "ca.key") -CAcreateserial -out (Join-Path $CertsDir "tpp.crt") -days 365 -extfile (Join-Path $CertsDir "tpp-ext.cnf") -extensions v3_req
Remove-Item (Join-Path $CertsDir "tpp.csr"), (Join-Path $CertsDir "tpp-ext.cnf") -ErrorAction SilentlyContinue

# 4. Resource Server Certificate
Write-Host ">> [4/4] Generating Resource Server TLS Certificate..." -ForegroundColor Yellow
& $OpenSSLExe req -new -newkey rsa:2048 -keyout (Join-Path $CertsDir "rs.key") -out (Join-Path $CertsDir "rs.csr") -nodes -subj "/CN=resource-server-fapi/O=OpenBanking Research/C=VN"

@"
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = resource-server-fapi
DNS.2 = localhost
DNS.3 = $RsHost
IP.1 = 127.0.0.1
IP.2 = $HostIp
"@ | Out-File -Encoding ASCII (Join-Path $CertsDir "rs-ext.cnf")

& $OpenSSLExe x509 -req -in (Join-Path $CertsDir "rs.csr") -CA (Join-Path $CertsDir "ca.crt") -CAkey (Join-Path $CertsDir "ca.key") -CAcreateserial -out (Join-Path $CertsDir "rs.crt") -days 365 -extfile (Join-Path $CertsDir "rs-ext.cnf") -extensions v3_req
Remove-Item (Join-Path $CertsDir "rs.csr"), (Join-Path $CertsDir "rs-ext.cnf") -ErrorAction SilentlyContinue

# 5. Automatically Synchronize TPP Certificate Thumbprint to Keycloak Realm (AT-05)
$tppCrtPath = Join-Path $CertsDir "tpp.crt"
if (Test-Path $tppCrtPath) {
    $pemLines = Get-Content $tppCrtPath | Where-Object { $_ -notmatch '^-----' }
    $b64 = $pemLines -join ''
    $der = [System.Convert]::FromBase64String($b64)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash($der)
    $thumbprint = [System.Convert]::ToBase64String($hash).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Write-Host ">> Synchronizing TPP Certificate Thumbprint into Keycloak Realm: $thumbprint" -ForegroundColor Cyan

    $realmJsonPath = Join-Path $ScriptDir "auth-server\realm-config\traditional-fapi-realm.json"
    if (Test-Path $realmJsonPath) {
        $json = [System.IO.File]::ReadAllText($realmJsonPath)
        $targetReplacement = '{\"x5t#S256\":\"' + $thumbprint + '\"}'
        $updatedJson = [System.Text.RegularExpressions.Regex]::Replace($json, '\{\\"x5t#S256\\":\\"[^\\"]*\\"', [System.Text.RegularExpressions.Regex]::Escape($targetReplacement).Replace('\', '\\'))
        [System.IO.File]::WriteAllText($realmJsonPath, $updatedJson, [System.Text.Encoding]::UTF8)
        Write-Host "   Updated traditional-fapi-realm.json with new thumbprint." -ForegroundColor Green
    }
}

Write-Host "============================================================" -ForegroundColor Green
Write-Host "All TLS certificates generated and synchronized successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

