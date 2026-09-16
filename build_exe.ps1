param(
    [string]$Python = ".\.venv\Scripts\python.exe",
    [switch]$Clean,
    [switch]$RebuildSemgrep,
    [switch]$InstallDependencies,
    [switch]$StopRunning
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path $Python)) {
    throw "Python virtual environment was not found: $Python"
}

if ($InstallDependencies) {
    Write-Host "Installing or updating build dependencies..."
    & $Python -m pip install -r requirements-build.txt
} else {
    & $Python -c "import PyInstaller, semgrep, fastapi, openai" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Build dependencies are missing. Run: .\build_exe.ps1 -InstallDependencies"
    }
}

$stage = Join-Path $root "build_exe"
$release = Join-Path $root "release"
$semgrepRunner = Join-Path $stage "semgrep-runner"
$releaseApp = Join-Path $release "API-Scan-Tool"

if ($Clean -and (Test-Path $stage)) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
foreach ($directory in @($stage, $release)) {
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

# Semgrep is large and changes independently from the web application. Reuse
# its packaged runner by default; -RebuildSemgrep (or -Clean) forces a rebuild.
if ($Clean -or $RebuildSemgrep -or -not (Test-Path (Join-Path $semgrepRunner "semgrep-runner.exe"))) {
    Write-Host "Building Semgrep runner..."
    $semgrepArgs = @("--noconfirm", "--onedir", "--name", "semgrep-runner", "--distpath", $stage, "--workpath", (Join-Path $stage "work-semgrep"), "--specpath", $stage, "--collect-all", "semgrep", "semgrep_runner.py")
    if ($Clean) { $semgrepArgs += "--clean" }
    & $Python -m PyInstaller @semgrepArgs
} else {
    Write-Host "Reusing existing Semgrep runner (use -RebuildSemgrep to rebuild it)."
}

# Replacing a running EXE fails on Windows, so give a concise fix instead of
# leaving a partially deleted release folder.
$runningApp = Get-Process -Name "API-Scan-Tool" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $releaseApp "API-Scan-Tool.exe") }
if ($runningApp) {
    if (-not $StopRunning) {
        throw "API-Scan-Tool.exe is still running. Close it, or run: .\build_exe.ps1 -StopRunning"
    }
    Write-Host "Stopping the currently running API-Scan-Tool.exe..."
    $runningApp | Stop-Process -Force
    $runningApp | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
}
if (Test-Path $releaseApp) {
    Remove-Item -LiteralPath $releaseApp -Recurse -Force
}

Write-Host "Building web application..."
$appArgs = @("--noconfirm", "--onedir", "--windowed", "--name", "API-Scan-Tool", "--distpath", $release, "--workpath", (Join-Path $stage "work-app"), "--specpath", $stage, "--add-data", "$root/api_scan_tool/templates;api_scan_tool/templates", "--add-data", "$root/api_scan_tool/static;api_scan_tool/static", "--add-data", "$root/api_scan_tool/rules;api_scan_tool/rules", "--add-data", "$semgrepRunner;semgrep", "--collect-all", "uvicorn", "--collect-all", "fastapi", "--collect-all", "starlette", "--collect-all", "openai", "--collect-all", "certifi", "launcher.py")
if ($Clean) { $appArgs += "--clean" }
& $Python -m PyInstaller @appArgs

Copy-Item (Join-Path $root ".env.example") (Join-Path $releaseApp ".env.example") -Force
Write-Host "Build complete: $releaseApp\API-Scan-Tool.exe"
