param(
    [string]$RunDir = "intake\\web\\hexstrike-ai\\run-juice-001",
    [string]$HexstrikeRoot = "/home/kali/hexstrike-ai"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$runPath = if ([System.IO.Path]::IsPathRooted($RunDir)) {
    $RunDir
} else {
    Join-Path $repoRoot $RunDir
}
$discoveryDir = Join-Path (Join-Path $runPath "raw") "runtime-discovery"
New-Item -ItemType Directory -Force -Path $discoveryDir | Out-Null

function Write-Evidence {
    param(
        [string]$Name,
        [scriptblock]$Script
    )

    $path = Join-Path $discoveryDir $Name
    $header = @(
        "# captured_at=$(Get-Date -Format o)",
        "# cwd=$(Get-Location)",
        ""
    )
    $body = & $Script 2>&1 | Out-String
    ($header + $body) | Set-Content -Path $path -Encoding utf8
}

function Write-Note {
    param(
        [string]$Name,
        [string]$Content
    )

    $path = Join-Path $discoveryDir $Name
    $Content | Set-Content -Path $path -Encoding utf8
}

Write-Evidence "get-command.txt" {
    "## Get-Command hexstrike* -All | Format-List *"
    Get-Command hexstrike* -All | Format-List *
    ""
    "## Get-Alias | Where-Object Name -like 'hexstrike*'"
    Get-Alias | Where-Object { $_.Name -like "hexstrike*" } | Format-List *
}

Write-Evidence "where.txt" {
    "## where.exe hexstrike_server"
    cmd /c "where hexstrike_server"
    ""
    "## where.exe hexstrike_mcp"
    cmd /c "where hexstrike_mcp"
    ""
    "## where.exe hexstrike"
    cmd /c "where hexstrike"
}

Write-Evidence "which.txt" {
    "## Get-Command which"
    Get-Command which -All | Format-List *
    ""
    "## bash -lc 'which ...'"
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if ($bash) {
        bash -lc "which hexstrike_server; which hexstrike_mcp; which hexstrike"
    } else {
        "bash not available in this session"
    }
}

Write-Evidence "pip-show.txt" {
    "## python --version"
    python --version
    ""
    "## python -m pip show hexstrike-ai"
    python -m pip show hexstrike-ai
    ""
    "## python -m pip show hexstrike-mcp"
    python -m pip show hexstrike-mcp
    ""
    "## python -m pip list | Select-String -Pattern 'hexstrike'"
    python -m pip list | Select-String -Pattern "hexstrike"
}

Write-Evidence "entrypoints.txt" {
    @'
## python entry_points / site-packages inspection
'@
    @'
import importlib.metadata as m
import site
import sys
print("sys.executable=", sys.executable)
print("console_scripts containing hexstrike:")
found = False
for ep in m.entry_points(group="console_scripts"):
    text = f"{ep.name} -> {ep.value}"
    if "hexstrike" in text.lower():
        found = True
        print("  ", text)
if not found:
    print("   <none>")
print("distributions containing hexstrike:")
found = False
for dist in m.distributions():
    name = dist.metadata.get("Name", "")
    if "hexstrike" in name.lower():
        found = True
        print("  ", name, dist.version)
if not found:
    print("   <none>")
print("site.getsitepackages=")
try:
    for item in site.getsitepackages():
        print("  ", item)
except Exception as exc:
    print("  ERROR", type(exc).__name__, exc)
print("site.getusersitepackages=", site.getusersitepackages())
'@ | python -
    ""
    "## npm metadata"
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($npm) {
        npm root -g
        npm prefix -g
        npm list -g --depth=0 | Select-String -Pattern "hexstrike"
    } else {
        "npm not available in this session"
    }
}

Write-Evidence "filesystem-inspection-local.txt" {
    "## PATH"
    $env:PATH -split [System.IO.Path]::PathSeparator
    ""
    "## metadata files in repo"
    if (Get-Command rg -ErrorAction SilentlyContinue) {
        rg --files -g "pyproject.toml" -g "package.json" -g "setup.py" -g "setup.cfg" -g "hatch.toml" -g "poetry.lock" .
    } else {
        Get-ChildItem -Path . -Recurse -File -Include pyproject.toml,package.json,setup.py,setup.cfg,hatch.toml,poetry.lock |
            ForEach-Object { $_.FullName }
    }
}

$serverScript = Join-Path $HexstrikeRoot "hexstrike_server.py"
$mcpScript = Join-Path $HexstrikeRoot "hexstrike_mcp.py"
$mcpConfig = Join-Path $HexstrikeRoot "hexstrike-ai-mcp.json"
$venvPython = Join-Path $HexstrikeRoot "hexstrike-env/bin/python"

if (Test-Path $HexstrikeRoot) {
    Write-Evidence "filesystem-inspection.txt" {
        "## Get-ChildItem $HexstrikeRoot"
        Get-ChildItem -Force $HexstrikeRoot
        ""
        "## relevant files under root"
        Get-ChildItem -Path $HexstrikeRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match "^README" -or
                $_.Name -in @("package.json", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock", "hatch.toml", "hexstrike-ai-mcp.json", "hexstrike_server.py", "hexstrike_mcp.py")
            } |
            Select-Object -ExpandProperty FullName
    }

    Write-Evidence "mcp-tool-catalog.txt" {
        "## hexstrike-ai-mcp.json"
        if (Test-Path $mcpConfig) {
            Get-Content $mcpConfig
        }
        ""
        "## candidate tool definitions"
        if (Test-Path $mcpScript) {
            Select-String -Path $mcpScript -Pattern "def (burpsuite_alternative_scan|browser_agent_inspect|http_framework_test|http_set_scope|http_intruder)\(" -Context 0,8
        }
    }

    Write-Evidence "any-other-relevant-raw.txt" {
        "## README references"
        $readme = Join-Path $HexstrikeRoot "README.md"
        if (Test-Path $readme) {
            Select-String -Path $readme -Pattern "hexstrike_server.py|hexstrike_mcp.py|--debug|--port|--timeout" -Context 1,1
        }
        ""
        "## bundled venv packages"
        if (Test-Path $venvPython) {
            & $venvPython -m pip show selenium mcp
        } else {
            "Bundled venv python not found: $venvPython"
        }
    }

    if (Test-Path $venvPython -and (Test-Path $serverScript)) {
        Write-Evidence "help-hexstrike_server.txt" { & $venvPython $serverScript "--help" }
        Write-Evidence "version-hexstrike_server.txt" { & $venvPython $serverScript "--version" }
    } else {
        Write-Note "help-hexstrike_server.txt" "hexstrike_server.py or bundled venv python not accessible from this session."
        Write-Note "version-hexstrike_server.txt" "hexstrike_server.py or bundled venv python not accessible from this session."
    }

    if (Test-Path $venvPython -and (Test-Path $mcpScript)) {
        Write-Evidence "help-hexstrike_mcp.txt" { & $venvPython $mcpScript "--help" }
        Write-Evidence "version-hexstrike_mcp.txt" { & $venvPython $mcpScript "--version" }
    } else {
        Write-Note "help-hexstrike_mcp.txt" "hexstrike_mcp.py or bundled venv python not accessible from this session."
        Write-Note "version-hexstrike_mcp.txt" "hexstrike_mcp.py or bundled venv python not accessible from this session."
    }
} else {
    Write-Note "filesystem-inspection.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
    Write-Note "mcp-tool-catalog.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
    Write-Note "any-other-relevant-raw.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
    Write-Note "help-hexstrike_server.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
    Write-Note "version-hexstrike_server.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
    Write-Note "help-hexstrike_mcp.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
    Write-Note "version-hexstrike_mcp.txt" "HexStrike root is not accessible from this session: $HexstrikeRoot"
}

Write-Host "Runtime discovery evidence written to $discoveryDir"
