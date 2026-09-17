param(
    [string]$Exe = ".\release\Code-Check\Code-Check.exe"
)

$ErrorActionPreference = "Stop"
$resolvedExe = (Resolve-Path $Exe).Path
$process = Start-Process -FilePath $resolvedExe -ArgumentList "--no-browser" -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(20)
    do {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:8787/api/health" -TimeoutSec 2
            if ($health.status -eq "ok") {
                Write-Host "Portable EXE self-check passed: local web server started successfully."
                exit 0
            }
        } catch { Start-Sleep -Milliseconds 500 }
    } while ((Get-Date) -lt $deadline)
    throw "Code-Check.exe did not expose a healthy local server within 20 seconds."
} finally {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}
