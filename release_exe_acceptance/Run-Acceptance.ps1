# Launch from the project's root, no elevation required.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $root '.venv-win\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Virtual environment Python not found: $python"
}
$script = Join-Path $PSScriptRoot 'check_exe.py'
Push-Location $root
try {
    & $python $script --root $root --out 'release_exe_acceptance_result.json'
    $exitCode = $LASTEXITCODE
    Write-Host "Acceptance script exit status: $exitCode"
    $global:LASTEXITCODE = $exitCode
    if ($exitCode -ne 0) { Write-Warning "Review release_exe_acceptance_result.json before release." }
} finally {
    Pop-Location
}
