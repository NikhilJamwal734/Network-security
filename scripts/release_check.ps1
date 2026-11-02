
# ============================================================
# API-008.5
# Firewall Configuration Analyzer
# Final Regression and Release Check
#
# Run from the project root:
#   .\scripts\release_check.ps1
# ============================================================

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = (
    Resolve-Path (
        Join-Path $PSScriptRoot ".."
    )
).Path

$FrontendRoot = Join-Path $ProjectRoot "frontend"

Write-Host ""
Write-Host "============================================"
Write-Host " FIREWALL ANALYZER - API-008.5"
Write-Host " FINAL RELEASE CHECK"
Write-Host "============================================"
Write-Host ""

Push-Location $ProjectRoot

try {

    # --------------------------------------------------------
    # STEP 1 — BACKEND SECURITY AND REGRESSION TESTS
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "[1/3] Running backend tests..." `
        -ForegroundColor Cyan

    & python -m pytest -q

    if ($LASTEXITCODE -ne 0) {
        throw "Backend tests failed."
    }

    Write-Host ""
    Write-Host "Backend tests passed." `
        -ForegroundColor Green

    # --------------------------------------------------------
    # STEP 2 — PERFORMANCE BENCHMARK
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "[2/3] Running API benchmark..." `
        -ForegroundColor Cyan

    $BenchmarkPath = Join-Path `
        $ProjectRoot `
        "scripts\benchmark_analysis.py"

    if (Test-Path $BenchmarkPath) {

        & python -m scripts.benchmark_analysis --runs 20

        if ($LASTEXITCODE -ne 0) {
            throw "API performance benchmark failed."
        }

        Write-Host ""
        Write-Host "API benchmark completed." `
            -ForegroundColor Green

    }
    else {

        Write-Host `
            "Benchmark script not found; skipping benchmark." `
            -ForegroundColor Yellow

    }

    # --------------------------------------------------------
    # STEP 3 — FRONTEND PRODUCTION BUILD
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "[3/3] Building React frontend..." `
        -ForegroundColor Cyan

    if (-not (Test-Path $FrontendRoot)) {
        throw "Frontend directory not found."
    }

    Push-Location $FrontendRoot

    try {

        & npm.cmd run build

        if ($LASTEXITCODE -ne 0) {
            throw "Frontend production build failed."
        }

    }
    finally {
        Pop-Location
    }

    Write-Host ""
    Write-Host "============================================" `
        -ForegroundColor Green

    Write-Host " AUTOMATED CHECKS PASSED" `
        -ForegroundColor Green

    Write-Host "============================================" `
        -ForegroundColor Green

    Write-Host ""
    Write-Host "Remaining manual checks:"
    Write-Host " - Desktop layout"
    Write-Host " - Tablet layout"
    Write-Host " - Mobile layout"
    Write-Host " - JSON download"
    Write-Host " - PDF download"
    Write-Host " - Browser console errors"
    Write-Host ""

}
finally {
    Pop-Location
}
