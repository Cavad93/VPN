<#
.SYNOPSIS
    Watchdog — keeps the VPN server alive. Run in a separate PowerShell window.

.DESCRIPTION
    Checks every 10 seconds if cavad-vpn.exe is running.
    If not — kills any zombie process, rebuilds binary, waits for port, starts server.

.EXAMPLE
    .\watchdog.ps1
#>

param(
    [string]$RepoDir = "C:\CavadVPN\repo",
    [string]$BinaryPath = "C:\CavadVPN\cavad-vpn.exe",
    [string]$ServerArgs = "-addr 0.0.0.0:38947 -tun-cidr 10.8.0.1/24 -api-addr 127.0.0.1:8080",
    [string]$VlessArgs = "",  # e.g. "-vless-addr 0.0.0.0:8444 -vless-cert C:\CavadVPN\cert.pem -vless-key C:\CavadVPN\key.pem"
    [int]$CheckInterval = 10,
    [int]$Port = 38947
)

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $Message"
}

$FullArgs = $ServerArgs
if ($VlessArgs) { $FullArgs = "$ServerArgs $VlessArgs" }

Write-Log "Watchdog started. Monitoring cavad-vpn.exe..."
Write-Log "Binary: $BinaryPath"
Write-Log "Args: $FullArgs"
Write-Log ""

while ($true) {
    $proc = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue

    if (-not $proc) {
        Write-Log "SERVER DOWN! Full restart sequence..."

        # 1. Kill any zombie process
        Write-Log "  [1/4] Killing any remaining processes..."
        Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2

        # 2. Build binary
        Write-Log "  [2/4] Building binary..."
        $serverDir = Join-Path $RepoDir "server"
        Push-Location $serverDir
        try {
            $buildOutput = go build -o $BinaryPath -ldflags "-s -w" . 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "  Build OK"
            } else {
                Write-Log "  Build FAILED: $buildOutput"
                Write-Log "  Will try starting existing binary..."
            }
        } finally {
            Pop-Location
        }

        # 3. Wait for port to free up
        Write-Log "  [3/4] Waiting for port $Port..."
        for ($i = 0; $i -lt 15; $i++) {
            $inUse = netstat -ano 2>$null | Select-String ":$Port\s" | Select-String "LISTENING"
            if (-not $inUse) { break }
            Write-Log "  Port $Port still in use, waiting..."
            Start-Sleep -Seconds 2
        }

        # 4. Start server with retry
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            Write-Log "  [4/4] Starting server (attempt $attempt/3)..."
            Start-Process -FilePath $BinaryPath -ArgumentList $FullArgs -WindowStyle Normal
            Start-Sleep -Seconds 5

            $check = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue
            if ($check) {
                Write-Log "  Server running (PID $($check.Id))"
                break
            }
            Write-Log "  Failed, retrying in 5s..."
            Start-Sleep -Seconds 5
        }
    }

    Start-Sleep -Seconds $CheckInterval
}
