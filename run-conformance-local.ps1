# ============================================================
# Local Conformance Test Runner
# ============================================================
# Conformance calls the services directly, so it runs with the application ports OPENED by a compose
# override (evaluation/configs/conformance-ports/). The perf runs never use those overrides.
#
# For each baseline this script: stops everything, starts the stack with the override and the conformance
# profile (Spring profile "conformance" / CONFORMANCE_TEST_MODE), waits for it, runs conformance_v3.py, and
# stops the stack again (containers are kept).
#
# Usage:
#   .\run-conformance-local.ps1                       # B0-C0, B1-C0, B1-C2
#   .\run-conformance-local.ps1 -Baseline B1-C0       # one baseline
#   .\run-conformance-local.ps1 -Baseline B0-C0 -SkipStart   # use the stack that is already running
# ============================================================

param (
    [Parameter(Position=0)]
    [ValidateSet("B0-C0", "B1-C0", "B1-C2", "")]
    [string]$Baseline = "",
    [switch]$SkipStart,
    [switch]$KeepRunning,
    [switch]$SkipQuantum      # B1-C2: skip the HY-* hybrid suite. Those cases are required, so skipping
                              # them leaves the gate short of "pass" and the run exits non-zero.
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Ports = Join-Path $ScriptDir "evaluation\configs\conformance-ports"

$Stacks = @{
    "B0-C0" = @{ Compose = "traditional-fapi\docker-compose.yml";             Override = "b0.yml" }
    "B1-C0" = @{ Compose = "wallet-vc-model-classical\docker-compose.yml";     Override = "b1.yml" }
    "B1-C2" = @{ Compose = "wallet-vc-model\docker-compose.yml";               Override = "b1.yml" }
}
$Ready = @{
    "B0-C0" = @("https://localhost:8443/realms/traditional-fapi/.well-known/openid-configuration", "https://localhost:3000/api/config")
    "B1-C0" = @("https://localhost:9443/.well-known/openid-credential-issuer", "http://localhost:6001/api/config", "http://localhost:5000/api/vcs")
    "B1-C2" = @("https://localhost:9443/.well-known/openid-credential-issuer", "http://localhost:6001/api/config", "http://localhost:5000/api/vcs")
}

function Set-ComposeEnvironment([string]$Config) {
    # What the containers see (they reach the host through host.docker.internal for B1).
    $env:SPRING_PROFILES_ACTIVE = "conformance"
    $env:CONFORMANCE_TEST_MODE  = "true"
    if ($Config -eq "B0-C0") {
        $env:BANK_HOST = "localhost"; $env:KEYCLOAK_HOST = "localhost"; $env:TPP_HOST = "localhost"; $env:WALLET_HOST = "localhost"
    } else {
        $env:BANK_HOST = "host.docker.internal"; $env:TPP_HOST = "host.docker.internal"
        $env:FRONTEND_BANK_HOST = "localhost"; $env:WALLET_HOST = "localhost"
    }
}

function Set-ClientEnvironment([string]$Config) {
    # What the Python suite calls: everything on localhost, application ports.
    $env:BANK_HOST = "localhost"; $env:KEYCLOAK_HOST = "localhost"; $env:FRONTEND_BANK_HOST = "localhost"
    $env:TPP_HOST = "localhost"; $env:WALLET_HOST = "localhost"; $env:RS_HOST = "localhost"
    $env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
    $env:B0_TPP_URL      = "https://localhost:3000"
    $env:B0_RS_URL       = "http://localhost:4000"     # cases that do not test TLS (certificate sent in a header)
    $env:B0_RS_TLS_URL   = "https://localhost:8443"    # the certificate-binding case: real mTLS through the bank gateway
    $env:VDAM_ISSUER_URL = "http://localhost:7000"
    $env:VDAM_DAS_URL    = "http://localhost:7000"
    $env:VDAM_RS_URL     = "http://localhost:4000"
    $env:VDAM_TPP_URL    = "http://localhost:6001"
    $env:VDAM_WALLET_URL = "http://localhost:5000"
}

function Stop-All {
    # "down", not "stop": the single-host compose and the per-role composes (used for the VM client) use different
    # project names but the same container names, so leftover containers of one would block the other.
    powershell -ExecutionPolicy Bypass -File (Join-Path $ScriptDir "manage.ps1") down all | Out-Null
}

function Start-Stack([string]$Config) {
    $stack = $Stacks[$Config]
    Set-ComposeEnvironment $Config
    Write-Host "Starting $Config with the conformance port override..." -ForegroundColor Cyan
    Stop-All
    # docker writes progress to stderr; only the exit code decides success (PowerShell 5.1 would treat stderr as an error).
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = docker compose -f (Join-Path $ScriptDir $stack.Compose) -f (Join-Path $Ports $stack.Override) up -d --build 2>&1
    $composeExit = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($composeExit -ne 0) { throw "docker compose up failed for ${Config}: $($out -join ' ')" }
    $deadline = (Get-Date).AddSeconds(240)
    foreach ($url in $Ready[$Config]) {
        while ($true) {
            $code = & curl.exe -sk -m 5 -o NUL -w "%{http_code}" $url
            if ($code -eq "200") { break }
            if ((Get-Date) -gt $deadline) { throw "Readiness timeout for $url (last HTTP $code)" }
            Start-Sleep -Seconds 3
        }
    }
    Write-Host "$Config is ready." -ForegroundColor Green
}

function Run-Conformance([string]$Config) {
    $RunId = "local-conf-$($Config.ToLower().Replace('-',''))-$Timestamp"
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Running conformance: $Config  (run-id: $RunId)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    Set-ClientEnvironment $Config
    Push-Location $ScriptDir
    try {
        # Out-Host keeps python's output out of this function's return value (which must be the exit code only).
        $extra = @()
        if (-not $SkipQuantum -and $Config -eq "B1-C2") { $extra += "--include-quantum" }
        python evaluation/bin/conformance/conformance_v3.py --configuration $Config --run-id $RunId @extra | Out-Host
        $ExitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }

    if ($ExitCode -eq 0) {
        Write-Host "[PASS] $Config conformance PASSED (exit 0)" -ForegroundColor Green
    } elseif ($ExitCode -eq 2) {
        Write-Host "[FAIL] $Config conformance completed with failures (exit 2)" -ForegroundColor Yellow
    } else {
        Write-Host "[ERROR] $Config conformance exited with code $ExitCode" -ForegroundColor Red
    }
    return $ExitCode
}

$Timestamp = (Get-Date -Format "yyyyMMddTHHmmssZ")
$Targets = if ($Baseline) { @($Baseline) } else { @("B0-C0", "B1-C0", "B1-C2") }

$OverallExit = 0
foreach ($t in $Targets) {
    if (-not $SkipStart) { Start-Stack $t }
    $code = Run-Conformance $t
    if ($code -ne 0) { $OverallExit = $code }
    if (-not $SkipStart -and -not $KeepRunning) { Stop-All }
}

Write-Host ""
if ($OverallExit -eq 0) {
    Write-Host "All conformance suites PASSED." -ForegroundColor Green
} else {
    Write-Host "One or more conformance suites had failures -- see evaluation/evidence/conformance/." -ForegroundColor Yellow
}
exit $OverallExit
