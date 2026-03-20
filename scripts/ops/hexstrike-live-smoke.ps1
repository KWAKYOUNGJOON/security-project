param(
    [string]$RunDir = "intake\\web\\hexstrike-ai\\run-juice-001",
    [string]$ServerUrl = "http://127.0.0.1:8888",
    [string]$Target = "http://192.168.10.130:3000"
)

$ErrorActionPreference = "Stop"

if ($Target -ne "http://192.168.10.130:3000") {
    throw "This script is restricted to the approved local lab target http://192.168.10.130:3000"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$runPath = if ([System.IO.Path]::IsPathRooted($RunDir)) {
    $RunDir
} else {
    Join-Path $repoRoot $RunDir
}
$rawDir = Join-Path $runPath "raw"
$outputPath = Join-Path $rawDir "hexstrike-result.json"
New-Item -ItemType Directory -Force -Path $rawDir | Out-Null

$body = [ordered]@{
    target = $Target
    scan_type = "passive"
    headless = $true
    max_depth = 1
    max_pages = 1
}

Write-Host "Planned request:"
Write-Host "  POST $ServerUrl/api/tools/burpsuite-alternative"
Write-Host "  target=$Target"
Write-Host "  scan_type=passive"
Write-Host "  headless=true"
Write-Host "  max_depth=1"
Write-Host "  max_pages=1"
Write-Host ""
Write-Host "Stop immediately if latency spikes, repeated resets/timeouts appear, 5xx grows, Ubuntu resource pressure is visible, or scope escapes the canonical target."

$response = Invoke-WebRequest `
    -Method Post `
    -Uri ($ServerUrl.TrimEnd("/") + "/api/tools/burpsuite-alternative") `
    -ContentType "application/json" `
    -Body ($body | ConvertTo-Json -Depth 5) `
    -SkipHttpErrorCheck

$rawContent = $response.Content
try {
    $parsed = $rawContent | ConvertFrom-Json -ErrorAction Stop
    $rawContent = $parsed | ConvertTo-Json -Depth 20
} catch {
}

$rawContent | Set-Content -Path $outputPath -Encoding utf8

if ($response.StatusCode -ge 400) {
    throw "HexStrike server returned HTTP $($response.StatusCode). Raw response saved to $outputPath"
}

Write-Host "Raw response saved to $outputPath"
