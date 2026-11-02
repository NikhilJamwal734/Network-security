# PowerShell 5.1+; colourizes JSONL display without changing on-disk logs.
param(
    [ValidateSet('application','api_access','upload_audit','security_analysis','error')]
    [string] $Stream = 'security_analysis',
    [int] $Tail = 30,
    [switch] $NoWait
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sourceLogs = Join-Path $root 'logs'
$exeLogs = Join-Path $env:LOCALAPPDATA 'FirewallAnalyzer\logs'
$directory = if (Test-Path $sourceLogs) { $sourceLogs } elseif (Test-Path $exeLogs) { $exeLogs } else { $sourceLogs }
$file = Join-Path $directory "$Stream.log"
if (-not (Test-Path -LiteralPath $file)) {
    Write-Host "Log file not created yet: $file" -ForegroundColor Yellow
    Write-Host 'Start the backend and perform an analysis, or select a different stream.'
    exit 1
}
Write-Host "Monitoring: $file" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop. Original JSON log file is unchanged." -ForegroundColor DarkGray
$readerArgs = @{ LiteralPath = $file; Tail = [Math]::Max(1, $Tail) }
if (-not $NoWait) { $readerArgs['Wait'] = $true }
Get-Content @readerArgs | ForEach-Object {
    try {
        $row = $_ | ConvertFrom-Json
        $event = [string]$row.event
        $status = 0
        if ($null -ne $row.status_code) { $status = [int]$row.status_code }
        $color = 'Cyan'
        $level = 'INFO'
        if ($event -match '(failed|rejected|api_failure)' -or $status -ge 500) {
            $color = 'Red'; $level = 'ERROR'
        } elseif ($event -match 'warning' -or $status -ge 400) {
            $color = 'Yellow'; $level = 'WARN'
        } elseif ($event -match '(completed|accepted)') {
            $color = 'Green'; $level = 'SUCCESS'
        }
        $when = [string]$row.timestamp_utc
        $filename = if ($row.filename) { " | File: $($row.filename)" } else { '' }
        $platform = if ($row.platform) { " | Platform: $($row.platform)" } else { '' }
        $findings = if ($null -ne $row.finding_count) { " | Findings: $($row.finding_count)" } else { '' }
        Write-Host "[$when] [$level] $event$filename$platform$findings" -ForegroundColor $color
    } catch {
        Write-Host 'Ignored an invalid JSON log entry.' -ForegroundColor DarkGray
    }
}
