param(
    [Parameter(Mandatory = $true)][string]$PdfPath,
    [string]$ProjectRoot = ".",
    [string]$ApiUrl = "http://127.0.0.1:8000"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$python = Join-Path $root ".venv-win\Scripts\python.exe"
$checker = Join-Path $root "release_final\verify_final.py"
if (-not (Test-Path -LiteralPath $python)) { throw "Missing venv Python: $python" }
if (-not (Test-Path -LiteralPath $checker)) { throw "Missing final checker: $checker" }
if (-not (Test-Path -LiteralPath $PdfPath)) { throw "PDF file not found: $PdfPath" }
Push-Location $root
try {
    & $python $checker --root $root --run-tests --build-frontend --api-url $ApiUrl --pdf $PdfPath --bundled-vendor-samples --out (Join-Path $root "release_final_gate.json")
    $code = $LASTEXITCODE
    Write-Host "Final release gate exit code: $code (0=PASS, 1=FAIL, 2=INCOMPLETE)"
    if ($code -ne 0) { Write-Host "See release_final_gate.json and console output; do NOT build the EXE yet." }
    exit $code
} finally {
    Pop-Location
}
