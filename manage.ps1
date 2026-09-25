# ============================================================
# VDAM Master Orchestration Script (PowerShell / Windows)
# ============================================================
# Usage:
#   .\manage.ps1 <local|bank|tpp|wallet> prepare <baseline>   Build images, create containers (stopped)
#   .\manage.ps1 <local|bank|tpp|wallet> start   <baseline>   Start prepared containers (no rebuild)
#   .\manage.ps1 <local|bank|tpp|wallet> stop    <baseline>   Stop containers, keep them for the next start
#   .\manage.ps1 <local|bank|tpp|wallet> down    <baseline>   Remove containers and networks (volumes are kept)
#   .\manage.ps1 conformance start <baseline>                 Start "local", plus the direct application ports
#                                                              that the conformance suite calls (see
#                                                              evaluation/configs/conformance-ports/). Stop/down
#                                                              tear the same ports back down.
#   .\manage.ps1 stop [all | b0 | b1-classical | b1-pqc]      Stop, keep containers
#   .\manage.ps1 down [all | b0 | b1-classical | b1-pqc]      Remove containers
#   .\manage.ps1 status
# <baseline> is b0, b1-classical or b1-pqc (the wallet role has no b0).
# ============================================================

param (
    [Parameter(Position=0)]
    [string]$Target = "help",

    [Parameter(Position=1)]
    [string]$Action = "",

    [Parameter(Position=2)]
    [string]$Baseline = ""
)

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-Help {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  VDAM Master Orchestration CLI (Local & Multi-VM)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Usage:"
    Write-Host "  .\manage.ps1 <local|bank|tpp|wallet> prepare <baseline>  Build images, create containers (stopped)"
    Write-Host "  .\manage.ps1 <local|bank|tpp|wallet> start   <baseline>  Start prepared containers (no rebuild)"
    Write-Host "  .\manage.ps1 <local|bank|tpp|wallet> stop    <baseline>  Stop containers (kept for the next start)"
    Write-Host "  .\manage.ps1 <local|bank|tpp|wallet> down    <baseline>  Remove containers and networks"
    Write-Host "  .\manage.ps1 stop [all | b0 | b1-classical | b1-pqc]     Stop containers of a baseline"
    Write-Host "  .\manage.ps1 down [all | b0 | b1-classical | b1-pqc]     Remove containers of a baseline"
    Write-Host "  .\manage.ps1 status                                      Show running containers"
    Write-Host "  baseline: b0 | b1-classical | b1-pqc (the wallet role has no b0)"
    Write-Host ""
}

function Get-ComposeFile($role, $base) {
    switch ($role) {
        "local" {
            switch ($base) {
                "b0"           { return "$RootDir\traditional-fapi\docker-compose.yml" }
                "b1-classical" { return "$RootDir\wallet-vc-model-classical\docker-compose.yml" }
                "b1-pqc"       { return "$RootDir\wallet-vc-model\docker-compose.yml" }
            }
        }
        "conformance" {
            switch ($base) {
                "b0"           { return "$RootDir\evaluation\configs\conformance-ports\b0.yml" }
                "b1-classical" { return "$RootDir\evaluation\configs\conformance-ports\b1.yml" }
                "b1-pqc"       { return "$RootDir\evaluation\configs\conformance-ports\b1.yml" }
            }
        }
        "bank" {
            switch ($base) {
                "b0"           { return "$RootDir\traditional-fapi\docker-compose.bank.yml" }
                "b1-classical" { return "$RootDir\wallet-vc-model-classical\bank\docker-compose.yml" }
                "b1-pqc"       { return "$RootDir\wallet-vc-model\pqc-bank\docker-compose.yml" }
            }
        }
        "tpp" {
            switch ($base) {
                "b0"           { return "$RootDir\traditional-fapi\docker-compose.tpp.yml" }
                "b1-classical" { return "$RootDir\wallet-vc-model-classical\tpp\docker-compose.yml" }
                "b1-pqc"       { return "$RootDir\wallet-vc-model\pqc-tpp\docker-compose.yml" }
            }
        }
        "wallet" {
            switch ($base) {
                "b1-classical" { return "$RootDir\wallet-vc-model-classical\wallet\docker-compose.yml" }
                "b1-pqc"       { return "$RootDir\wallet-vc-model\pqc-wallet\docker-compose.yml" }
            }
        }
    }
    return $null
}

function Show-Status {
    Write-Host "`n=== Active VDAM Containers ===" -ForegroundColor Green
    $statusOutput = docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker status failed: $($statusOutput -join ' ')"
    }
    $statusOutput | Select-String -Pattern "fapi|classical|pqc|NAMES"
}

function Invoke-Compose([string[]]$ComposeFiles, [string[]]$ComposeArgs) {
    $fileArgs = @()
    foreach ($f in $ComposeFiles) { $fileArgs += @("-f", $f) }
    $output = docker compose @fileArgs @ComposeArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose '$($ComposeArgs -join ' ')' failed for '$($ComposeFiles -join ', ')': $($output -join ' ')"
    }
    return $output
}

# Baseline-wide operations. $Verb is "stop" (containers are kept) or "down" (containers are removed).
function Invoke-Baseline([string]$Verb, [string]$base) {
    Write-Host "Running '$Verb' for baseline: $base..." -ForegroundColor Yellow
    switch ($base) {
        "b0" {
            $files = @("traditional-fapi\docker-compose.yml", "traditional-fapi\docker-compose.bank.yml", "traditional-fapi\docker-compose.tpp.yml")
        }
        "b1-classical" {
            $files = @("wallet-vc-model-classical\docker-compose.yml", "wallet-vc-model-classical\bank\docker-compose.yml",
                       "wallet-vc-model-classical\tpp\docker-compose.yml", "wallet-vc-model-classical\wallet\docker-compose.yml")
        }
        "b1-pqc" {
            $files = @("wallet-vc-model\docker-compose.yml", "wallet-vc-model\pqc-bank\docker-compose.yml",
                       "wallet-vc-model\pqc-tpp\docker-compose.yml", "wallet-vc-model\pqc-wallet\docker-compose.yml")
        }
        default {
            foreach ($b in @("b0", "b1-classical", "b1-pqc")) { Invoke-Baseline $Verb $b }
            return
        }
    }
    foreach ($f in $files) { Invoke-Compose "$RootDir\$f" @($Verb) | Out-Null }
    Write-Host "Done." -ForegroundColor Green
}

# --- Main Dispatcher ---
if ($Target -eq "status") {
    Show-Status
    exit 0
}

if ($Target -in @("stop", "down")) {
    $scope = if ($Action) { $Action } else { "all" }
    Invoke-Baseline $Target $scope
    exit 0
}

if ($Target -in @("local", "bank", "tpp", "wallet", "conformance") -and $Action -in @("prepare", "start", "stop", "down")) {
    if (-not $Baseline) {
        Write-Host "Error: Baseline is required (e.g. b0, b1-classical, b1-pqc)." -ForegroundColor Red
        Show-Help
        exit 1
    }
    if ($Target -eq "conformance") {
        $composeFiles = @((Get-ComposeFile "local" $Baseline), (Get-ComposeFile "conformance" $Baseline))
    } else {
        $composeFiles = @(Get-ComposeFile $Target $Baseline)
    }
    foreach ($f in $composeFiles) {
        if (-not $f -or -not (Test-Path $f)) {
            Write-Host "Error: Compose file not found for Target '$Target' and Baseline '$Baseline'." -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "[$Action] $Target / $Baseline using: $($composeFiles -join ', ')" -ForegroundColor Cyan
    switch ($Action) {
        "prepare" {
            # Build the images and create the containers without starting them.
            Invoke-Compose $composeFiles @("up", "--no-start", "--build") | Write-Host
        }
        "start" {
            # Starts the prepared containers; never rebuilds, so a measurement never waits on a build.
            try {
                Invoke-Compose $composeFiles @("up", "-d", "--no-build") | Write-Host
            } catch {
                Write-Host "Error: start failed. If the images do not exist yet, run: .\manage.ps1 $Target prepare $Baseline" -ForegroundColor Red
                throw
            }
            Show-Status
        }
        "stop" { Invoke-Compose $composeFiles @("stop") | Write-Host }
        "down" { Invoke-Compose $composeFiles @("down") | Write-Host }
    }
    Write-Host "[$Action] $Target / $Baseline done." -ForegroundColor Green
    exit 0
}

Show-Help
