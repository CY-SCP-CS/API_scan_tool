param(
    [string]$Python = ".\.venv\Scripts\python.exe",
    [switch]$Clean,
    [switch]$InstallDependencies,
    [switch]$StopRunning
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
if (-not (Test-Path $Python)) { throw "Python virtual environment was not found: $Python" }
if ($InstallDependencies) {
    & $Python -m pip install -r requirements-build.txt
} else {
    & $Python -c "import PyInstaller, fastapi, openai" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Build dependencies are missing. Run: .\build_codecheck_exe.ps1 -InstallDependencies" }
}

$stage = Join-Path $root "build_codecheck"
$release = Join-Path $root "release"
$releaseApp = Join-Path $release "Code-Check"
if ($Clean -and (Test-Path $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
foreach ($directory in @($stage, $release)) { if (-not (Test-Path $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null } }
$running = Get-Process -Name "Code-Check" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $releaseApp "Code-Check.exe") }
if ($running) {
    if (-not $StopRunning) { throw "Code-Check.exe is still running. Close it, or run: .\build_codecheck_exe.ps1 -StopRunning" }
    $running | Stop-Process -Force
    $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
}
if (Test-Path $releaseApp) { Remove-Item -LiteralPath $releaseApp -Recurse -Force }

$args = @("--noconfirm", "--onedir", "--windowed", "--name", "Code-Check", "--distpath", $release, "--workpath", (Join-Path $stage "work"), "--specpath", $stage,
    "--add-data", "$root/codeCheck/codeCheck;codeCheck/codeCheck", "--collect-all", "uvicorn", "--collect-all", "fastapi", "--collect-all", "starlette", "--collect-all", "certifi", "codecheck_launcher.py")
if ($Clean) { $args += "--clean" }
& $Python -m PyInstaller @args
Copy-Item (Join-Path $root ".env.example") (Join-Path $releaseApp ".env.example") -Force
Write-Host "Build complete: $releaseApp\Code-Check.exe"
