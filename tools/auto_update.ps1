<#
.SYNOPSIS
    VPN Auto-Update Script for Windows Server.

.DESCRIPTION
    Checks GitHub for changes every 15 minutes. If updates found:
    - Pulls latest code (fast-forward only)
    - Rebuilds server binary (go build)
    - Restarts the VPN service WITHOUT breaking active connections
      (clients auto-reconnect within seconds)

.PARAMETER RepoDir
    Path to the VPN repository.

.PARAMETER Branch
    Git branch to track.

.PARAMETER Interval
    Check interval in seconds (default: 900 = 15 min).

.PARAMETER BinaryPath
    Path to output the compiled binary.

.PARAMETER ServiceName
    Windows service name (default: CavadVPN).

.PARAMETER Once
    Check once and exit.

.PARAMETER ServerArgs
    Command-line arguments passed to the VPN server binary on restart.

.EXAMPLE
    .\auto_update.ps1 -RepoDir C:\CavadVPN\repo -Branch claude/investigate-vpn-performance-IJ0iX
    .\auto_update.ps1 -RepoDir C:\CavadVPN\repo -ServerArgs "-addr 0.0.0.0:8443 -tun-cidr 10.8.0.1/24 -api-addr 127.0.0.1:8080"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$RepoDir,

    [string]$Branch = "claude/investigate-vpn-performance-IJ0iX",

    [int]$Interval = 900,

    [string]$BinaryPath = "C:\CavadVPN\cavad-vpn.exe",

    [string]$ServiceName = "CavadVPN",

    [string]$LogFile = "C:\CavadVPN\auto-update.log",

    [string]$ServerArgs = "-addr 0.0.0.0:8443 -tun-cidr 10.8.0.1/24 -api-addr 127.0.0.1:8080",

    [switch]$Once
)

$MaxRetries = 4

function Write-Log {
    param([string]$Level, [string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Invoke-GitFetch {
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            git -C $RepoDir fetch origin $Branch 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch {}
        $delay = [math]::Pow(2, $attempt)
        Write-Log "WARN" "git fetch failed (attempt $attempt/$MaxRetries), retrying in ${delay}s..."
        Start-Sleep -Seconds $delay
    }
    Write-Log "ERROR" "git fetch failed after $MaxRetries attempts"
    return $false
}

function Test-UpdateAvailable {
    if (-not (Invoke-GitFetch)) { return $false }

    $localHash  = (git -C $RepoDir rev-parse HEAD).Trim()
    $remoteHash = (git -C $RepoDir rev-parse "origin/$Branch").Trim()

    if ($localHash -eq $remoteHash) {
        Write-Log "INFO" "Already up to date ($($localHash.Substring(0,7)))"
        return $false
    }

    Write-Log "INFO" "Update available: $($localHash.Substring(0,7)) -> $($remoteHash.Substring(0,7))"
    return $true
}

function Invoke-Update {
    Write-Log "INFO" "Pulling latest changes..."

    # Stash local changes if any
    $diff = git -C $RepoDir diff --quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "WARN" "Stashing local changes..."
        git -C $RepoDir stash push -m "auto-update-$(Get-Date -Format 'yyyyMMddHHmmss')" 2>&1 | Out-Null
    }

    # Fast-forward merge
    $mergeResult = git -C $RepoDir merge --ff-only "origin/$Branch" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "ERROR" "Fast-forward merge failed: $mergeResult"
        return $false
    }

    $newHash = (git -C $RepoDir rev-parse --short HEAD).Trim()
    Write-Log "INFO" "Updated to $newHash"
    return $true
}

function Invoke-Rebuild {
    Write-Log "INFO" "Building server binary..."
    $serverDir = Join-Path $RepoDir "server"
    $newBinary = "$BinaryPath.new"

    Push-Location $serverDir
    try {
        $buildOutput = go build -o $newBinary -ldflags "-s -w" . 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR" "Build failed: $buildOutput"
            Remove-Item -Path $newBinary -ErrorAction SilentlyContinue
            return $false
        }
    } finally {
        Pop-Location
    }

    # Atomic swap: can't rename over running exe on Windows,
    # so we rename old → .bak, then new → target
    $bakPath = "$BinaryPath.bak"
    Remove-Item -Path $bakPath -ErrorAction SilentlyContinue

    if (Test-Path $BinaryPath) {
        Rename-Item -Path $BinaryPath -NewName (Split-Path $bakPath -Leaf) -ErrorAction SilentlyContinue
    }
    Rename-Item -Path $newBinary -NewName (Split-Path $BinaryPath -Leaf)

    Write-Log "INFO" "Binary updated: $BinaryPath"
    return $true
}

function Invoke-GracefulRestart {
    # Try Windows Service first
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Log "INFO" "Restarting Windows service '$ServiceName'..."
        Restart-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 3

        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc.Status -eq 'Running') {
            Write-Log "INFO" "Service restarted successfully"
            return
        }
        Write-Log "ERROR" "Service did not restart"
        return
    }

    # Not a service — find and restart the process
    $proc = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Log "INFO" "Stopping process (PID $($proc.Id))..."
        Stop-Process -Id $proc.Id -Force

        # Wait for process to fully exit and release the port
        for ($i = 0; $i -lt 15; $i++) {
            Start-Sleep -Seconds 1
            $still = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue
            if (-not $still) { break }
        }
        if (Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue) {
            Write-Log "ERROR" "Old process did not exit after 15s"
            return
        }
        Write-Log "INFO" "Old process stopped"

        # Wait for port to be released (TCP TIME_WAIT)
        $port = 8443
        if ($ServerArgs -match '-addr\s+\S+:(\d+)') { $port = [int]$Matches[1] }
        for ($i = 0; $i -lt 10; $i++) {
            $inUse = netstat -ano | Select-String ":$port\s" | Select-String "LISTENING"
            if (-not $inUse) { break }
            Write-Log "INFO" "Port $port still in use, waiting..."
            Start-Sleep -Seconds 2
        }
    } else {
        Write-Log "INFO" "No running process found, starting fresh"
    }

    # Start server with retry (up to 3 attempts)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Write-Log "INFO" "Starting $BinaryPath (attempt $attempt/3)..."
        Start-Process -FilePath $BinaryPath -ArgumentList $ServerArgs -WindowStyle Hidden
        Start-Sleep -Seconds 3

        $newProc = Get-Process -Name "cavad-vpn" -ErrorAction SilentlyContinue
        if ($newProc) {
            Write-Log "INFO" "Server running (PID $($newProc.Id))"
            return
        }
        Write-Log "WARN" "Process not found after start, retrying in 5s..."
        Start-Sleep -Seconds 5
    }

    Write-Log "ERROR" "Failed to start server after 3 attempts. Start manually:"
    Write-Log "ERROR" "  $BinaryPath $ServerArgs"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
Write-Log "INFO" "Auto-update started: repo=$RepoDir branch=$Branch interval=${Interval}s"

if (-not (Test-Path (Join-Path $RepoDir ".git"))) {
    Write-Log "ERROR" "$RepoDir is not a git repository"
    exit 1
}

while ($true) {
    try {
        if (Test-UpdateAvailable) {
            if (Invoke-Update) {
                if (Invoke-Rebuild) {
                    Invoke-GracefulRestart
                }
            }
        }
    } catch {
        Write-Log "ERROR" "Unexpected error: $_"
    }

    if ($Once) {
        Write-Log "INFO" "One-shot mode, exiting."
        break
    }

    Write-Log "INFO" "Next check in ${Interval}s..."
    Start-Sleep -Seconds $Interval
}
