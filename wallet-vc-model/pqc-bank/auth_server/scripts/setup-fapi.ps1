# Setup FAPI 2.0 Client Policies via Keycloak Admin REST API (PowerShell)
$ErrorActionPreference = "Stop"

$KEYCLOAK_URL = if ($env:KEYCLOAK_URL) { $env:KEYCLOAK_URL } else { "http://localhost:8080" }
$REALM = "fapi-demo"
$ADMIN_USER = if ($env:KEYCLOAK_ADMIN) { $env:KEYCLOAK_ADMIN } else { "admin" }
$ADMIN_PASS = if ($env:KEYCLOAK_ADMIN_PASSWORD) { $env:KEYCLOAK_ADMIN_PASSWORD } else { "admin" }

Write-Host "=== FAPI 2.0 Setup Script ===" -ForegroundColor Cyan
Write-Host "Keycloak URL: $KEYCLOAK_URL"
Write-Host "Realm: $REALM"
Write-Host ""

# Wait for Keycloak to be ready
Write-Host "Waiting for Keycloak to start..."
$maxRetries = 60
$retryCount = 0
while ($retryCount -lt $maxRetries) {
    try {
        $health = Invoke-RestMethod -Uri "$KEYCLOAK_URL/" -Method Get -ErrorAction SilentlyContinue
        if ($health) {
            break
        }
    } catch { }
    Write-Host "  ... waiting ($retryCount/$maxRetries)"
    Start-Sleep -Seconds 5
    $retryCount++
}

if ($retryCount -ge $maxRetries) {
    Write-Host "ERROR: Keycloak did not start within timeout" -ForegroundColor Red
    exit 1
}
Write-Host "Keycloak is ready!" -ForegroundColor Green
Write-Host ""

# Get admin access token
Write-Host "Getting admin access token..."
$tokenBody = @{
    client_id  = "admin-cli"
    username   = $ADMIN_USER
    password   = $ADMIN_PASS
    grant_type = "password"
}
$tokenResponse = Invoke-RestMethod -Uri "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" `
    -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
$accessToken = $tokenResponse.access_token

if (-not $accessToken) {
    Write-Host "ERROR: Failed to get admin access token" -ForegroundColor Red
    exit 1
}
Write-Host "Got access token successfully" -ForegroundColor Green
Write-Host ""

# Headers for authenticated requests
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Check if realm exists
Write-Host "Checking realm '$REALM'..."
try {
    $realmInfo = Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM" `
        -Method Get -Headers $headers
    Write-Host "Realm '$REALM' exists" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Realm '$REALM' not found. Check realm import." -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Configure Client Policies for FAPI 2.0
Write-Host "Configuring FAPI 2.0 Client Policies..."
$policiesJson = @{
    policies = @(
        @{
            name        = "fapi-2-policy"
            description = "FAPI 2.0 Security Profile enforcement for all clients"
            enabled     = $true
            conditions  = @(
                @{
                    condition     = "any-client"
                    configuration = @{}
                }
            )
            profiles    = @("fapi-2-security-profile")
        }
    )
} | ConvertTo-Json -Depth 10

try {
    Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/client-policies/policies" `
        -Method Put -Headers $headers -Body $policiesJson
    Write-Host "FAPI 2.0 Client Policies configured successfully!" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Policy configuration issue - $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# Create custom scopes (banking, transfer)
Write-Host "Creating custom scopes (banking, transfer)..."
$customScopes = @(
    @{ name="banking"; protocol="openid-connect" },
    @{ name="transfer"; protocol="openid-connect" }
)
foreach ($s in $customScopes) {
    try {
        Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" -Method Post -Headers $headers -Body ($s | ConvertTo-Json) -ErrorAction Stop
        Write-Host "Created scope: $($s.name)" -ForegroundColor Green
    } catch {
        Write-Host "Scope $($s.name) might already exist." -ForegroundColor Yellow
    }
}

# Assign scopes to fapi-test-client
Write-Host "Assigning scopes to fapi-test-client..."
try {
    $client = (Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=fapi-test-client" -Method Get -Headers $headers)[0]
    $allScopes = Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" -Method Get -Headers $headers
    
    $bankingId = ($allScopes | Where-Object name -eq "banking").id
    $transferId = ($allScopes | Where-Object name -eq "transfer").id
    
    if ($bankingId) {
        Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/clients/$($client.id)/optional-client-scopes/$bankingId" -Method Put -Headers $headers
    }
    if ($transferId) {
        Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/clients/$($client.id)/optional-client-scopes/$transferId" -Method Put -Headers $headers
    }
    Write-Host "Scopes assigned successfully." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not assign scopes - $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# Verify configuration
Write-Host "=== Verification ===" -ForegroundColor Cyan

Write-Host "Checking client policies..."
$policies = Invoke-RestMethod -Uri "$KEYCLOAK_URL/admin/realms/$REALM/client-policies/policies" `
    -Method Get -Headers $headers
$policies | ConvertTo-Json -Depth 10 | Write-Host
Write-Host ""

Write-Host "OIDC Discovery endpoint:"
$discovery = Invoke-RestMethod -Uri "$KEYCLOAK_URL/realms/$REALM/.well-known/openid-configuration" -Method Get
$discovery | ConvertTo-Json -Depth 5 | Write-Host
Write-Host ""

Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. cd test-client && npm install && npm start"
Write-Host "  2. Open http://localhost:3000 in your browser"
Write-Host "  3. Open http://localhost:3000/inspector for Protocol Inspector"
Write-Host "  4. Keycloak Admin: $KEYCLOAK_URL/admin (admin/admin)"
