<#
.SYNOPSIS
    Watchdog — keeps the VPN server alive. Run in a separate PowerShell window.

.DESCRIPTION
    Checks every 10 seconds if cavad-vpn.exe is running.
    If not — waits for port to free up, then starts it.

.EXAMPLE
    .\watchdog.ps1
#>

param(
    [string]$BinaryPath = "C:\CavadVPN\cavad-vpn.exe",
    [string]$ServerArgs = "-addr 0.0.0.0:8443 -tun-cidr 10.8.0.1/24 -api-addr 127.0.0.1:8080",
    [int]$CheckInterval = 10,
    [int]$Port = 8443
)

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $Message"
}

Write-Log "Watchdog started. Monitoring cavad-vpn.exe..."
Write-Log "Binary: $BinaryPath"
Write-Log "Args: $ServerArgs"
Write-Log ""

while ($true) {
    $proc = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue

    if (-not $proc) {
        Write-Log "SERVER DOWN! Restarting..."

        # Wait for port to free up
        for ($i = 0; $i -lt 15; $i++) {
            $inUse = netstat -ano 2>$null | Select-String ":$Port\s" | Select-String "LISTENING"
            if (-not $inUse) { break }
            Write-Log "  Port $Port still in use, waiting..."
            Start-Sleep -Seconds 2
        }

        # Start server in THIS window so logs are visible
        Write-Log "  Starting server..."
        $process = Start-Process -FilePath $BinaryPath -ArgumentList $ServerArgs `
            -PassThru -WindowStyle Normal
        Start-Sleep -Seconds 3

        $check = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue
        if ($check) {
            Write-Log "  Server running (PID $($check.Id))"
        } else {
            Write-Log "  FAILED to start! Will retry in ${CheckInterval}s..."
        }
    }

    Start-Sleep -Seconds $CheckInterval
}
