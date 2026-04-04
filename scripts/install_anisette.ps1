<#
.SYNOPSIS
    Устанавливает Anisette-сервер на Windows Server для SideStore.

.DESCRIPTION
    SideStore на iPhone требует Anisette-сервер для переподписи приложений
    каждые 7 дней. Этот скрипт устанавливает и настраивает Anisette-сервер
    на том же Windows Server где работает VPN.

    Не требует Docker. Использует Apple Music for Windows для ADI библиотек.

    Шаги:
    1. Проверяет/устанавливает Apple Music for Windows (нужны ADI DLL)
    2. Скачивает alt_anisette_server.exe
    3. Настраивает как Windows Scheduled Task (авто-запуск)
    4. Открывает порт в фаерволе
    5. Выводит URL для SideStore

.PARAMETER InstallDir
    Директория установки (по умолчанию C:\CavadVPN\anisette)

.PARAMETER Port
    Порт HTTP сервера (по умолчанию 6969)

.PARAMETER Uninstall
    Удалить Anisette-сервер

.EXAMPLE
    .\install_anisette.ps1
    .\install_anisette.ps1 -Port 6969
    .\install_anisette.ps1 -Uninstall
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallDir = "C:\CavadVPN\anisette",
    [int]$Port = 6969,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName = "CavadVPN_Anisette"
$LogFile = Join-Path $InstallDir "anisette_install.log"

# ─── Logging ───────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line -ForegroundColor $(switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "OK"    { "Green" }
        default { "White" }
    })
    if (Test-Path (Split-Path $LogFile -Parent)) {
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    }
}

# ─── Admin check ───────────────────────────────────────────────

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─── Uninstall ─────────────────────────────────────────────────

function Uninstall-Anisette {
    Write-Log "Удаление Anisette-сервера..."

    # Stop and remove scheduled task
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Задача $TaskName удалена" "OK"
    }

    # Kill process
    Get-Process -Name "alt_anisette_server" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Remove firewall rule
    Remove-NetFirewallRule -DisplayName "CavadVPN Anisette" -ErrorAction SilentlyContinue
    Write-Log "Правило фаервола удалено" "OK"

    Write-Log "Файлы в $InstallDir оставлены. Удалите вручную если не нужны."
    Write-Log "Anisette-сервер удалён" "OK"
}

# ─── Apple Music check ─────────────────────────────────────────

function Test-AppleMusic {
    # Check for Apple Music or iTunes installation
    $applePaths = @(
        "${env:ProgramFiles}\Apple\Apple Music",
        "${env:ProgramFiles(x86)}\Apple\Apple Music",
        "${env:ProgramFiles}\iTunes",
        "${env:ProgramFiles(x86)}\iTunes",
        "${env:LOCALAPPDATA}\Packages\AppleInc.AppleMusic*"
    )

    foreach ($p in $applePaths) {
        $resolved = Get-Item -Path $p -ErrorAction SilentlyContinue
        if ($resolved) {
            Write-Log "Apple Music/iTunes найден: $($resolved.FullName)" "OK"
            return $true
        }
    }

    # Check for ADI DLL directly
    $adiPaths = @(
        "${env:ProgramFiles}\Apple\Apple Music\adi.dll",
        "${env:ProgramFiles(x86)}\Apple\Apple Music\adi.dll",
        "${env:ProgramFiles}\iTunes\adi.dll",
        "${env:ProgramFiles(x86)}\iTunes\adi.dll",
        "${env:CommonProgramFiles}\Apple\Apple Application Support\adi.dll"
    )

    foreach ($p in $adiPaths) {
        if (Test-Path $p) {
            Write-Log "ADI library найдена: $p" "OK"
            return $true
        }
    }

    return $false
}

function Install-AppleMusic {
    Write-Log "Скачиваем Apple Music for Windows..."

    $installerUrl = "https://apps.microsoft.com/detail/9pfhdd62mxs1"
    Write-Log ""
    Write-Log "═══════════════════════════════════════════════════════════" "WARN"
    Write-Log "  Apple Music for Windows нужен для ADI библиотек." "WARN"
    Write-Log "" "WARN"
    Write-Log "  Установите вручную из Microsoft Store:" "WARN"
    Write-Log "  1. Откройте Microsoft Store" "WARN"
    Write-Log "  2. Найдите 'Apple Music'" "WARN"
    Write-Log "  3. Нажмите 'Установить'" "WARN"
    Write-Log "" "WARN"
    Write-Log "  Или установите iTunes:" "WARN"
    Write-Log "  https://www.apple.com/itunes/download/win64" "WARN"
    Write-Log "" "WARN"
    Write-Log "  После установки запустите этот скрипт снова." "WARN"
    Write-Log "═══════════════════════════════════════════════════════════" "WARN"

    # Try to open Microsoft Store
    try {
        Start-Process "ms-windows-store://pdp/?productid=9PFHDD62MXS1" -ErrorAction SilentlyContinue
    } catch {
        # Ignore if Store is not available
    }
}

# ─── Download Anisette server ──────────────────────────────────

function Get-AnisetteServer {
    $exePath = Join-Path $InstallDir "alt_anisette_server.exe"

    if (Test-Path $exePath) {
        Write-Log "alt_anisette_server.exe уже есть: $exePath" "OK"
        return $exePath
    }

    Write-Log ""
    Write-Log "═══════════════════════════════════════════════════════════" "WARN"
    Write-Log "  alt_anisette_server.exe нужно скачать вручную." "WARN"
    Write-Log "" "WARN"
    Write-Log "  Скачайте Windows-версию из одного из этих проектов:" "WARN"
    Write-Log "  - SideStore/SideServer-Windows (GitHub Releases)" "WARN"
    Write-Log "  - Dadoum/anisette-v3-server (GitHub Releases)" "WARN"
    Write-Log "" "WARN"
    Write-Log "  Поместите .exe файл в:" "WARN"
    Write-Log "    $InstallDir\alt_anisette_server.exe" "WARN"
    Write-Log "" "WARN"
    Write-Log "  Затем запустите этот скрипт снова." "WARN"
    Write-Log "═══════════════════════════════════════════════════════════" "WARN"

    return $null
}

# ─── Setup scheduled task ──────────────────────────────────────

function Install-AnisetteTask {
    param([string]$ExePath)

    # Remove existing task
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.State -eq "Running") {
            Stop-ScheduledTask -TaskName $TaskName
        }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # Create scheduled task that runs at startup
    $action = New-ScheduledTaskAction `
        -Execute $ExePath `
        -Argument "-p $Port" `
        -WorkingDirectory $InstallDir

    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Days 365)

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "CavadVPN Anisette Server for SideStore" | Out-Null

    Write-Log "Задача $TaskName создана (автозапуск при старте системы)" "OK"
}

# ─── Firewall ──────────────────────────────────────────────────

function Set-AnisetteFirewall {
    $rule = Get-NetFirewallRule -DisplayName "CavadVPN Anisette" -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule `
            -DisplayName "CavadVPN Anisette" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $Port `
            -Action Allow | Out-Null
        Write-Log "Правило фаервола добавлено (порт $Port TCP)" "OK"
    } else {
        Write-Log "Правило фаервола уже существует" "OK"
    }
}

# ─── Start server ─────────────────────────────────────────────

function Start-AnisetteServer {
    param([string]$ExePath)

    # Kill any existing instance
    Get-Process -Name "alt_anisette_server" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Start via scheduled task
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2

    # Verify it's running
    $proc = Get-Process -Name "alt_anisette_server" -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Log "Anisette-сервер запущен (PID: $($proc.Id))" "OK"
        return $true
    }

    # Fallback: start directly
    Write-Log "Попытка запуска напрямую..." "WARN"
    Start-Process -FilePath $ExePath -ArgumentList "-p $Port" `
        -WorkingDirectory $InstallDir -WindowStyle Hidden
    Start-Sleep -Seconds 2

    $proc = Get-Process -Name "alt_anisette_server" -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Log "Anisette-сервер запущен (PID: $($proc.Id))" "OK"
        return $true
    }

    Write-Log "Не удалось запустить Anisette-сервер" "ERROR"
    return $false
}

# ─── Test endpoint ─────────────────────────────────────────────

function Test-AnisetteEndpoint {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port" -UseBasicParsing -TimeoutSec 5
        if ($resp.StatusCode -eq 200) {
            Write-Log "Anisette endpoint отвечает на http://127.0.0.1:$Port" "OK"
            return $true
        }
    } catch {
        # Try /v3/client_info
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/v3/client_info" -UseBasicParsing -TimeoutSec 5
            if ($resp.StatusCode -eq 200) {
                Write-Log "Anisette endpoint отвечает на http://127.0.0.1:$Port/v3/client_info" "OK"
                return $true
            }
        } catch {
            Write-Log "Anisette endpoint не отвечает (может потребоваться время для инициализации)" "WARN"
        }
    }
    return $false
}

# ─── Summary ───────────────────────────────────────────────────

function Show-Summary {
    $serverIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown"
    } | Select-Object -First 1).IPAddress

    if (-not $serverIP) { $serverIP = "YOUR_SERVER_IP" }

    Write-Log ""
    Write-Log "═══════════════════════════════════════════════════════════"
    Write-Log "  Anisette-сервер установлен!" "OK"
    Write-Log ""
    Write-Log "  URL для SideStore:"
    Write-Log "    http://${serverIP}:$Port"
    Write-Log ""
    Write-Log "  Настройка SideStore на iPhone:"
    Write-Log "    1. Откройте SideStore -> Settings"
    Write-Log "    2. Найдите 'Anisette Server' / 'Custom Anisette URL'"
    Write-Log "    3. Введите: http://${serverIP}:$Port"
    Write-Log "    4. Сохраните и перезапустите SideStore"
    Write-Log ""
    Write-Log "  Управление:"
    Write-Log "    Статус:  Get-ScheduledTask -TaskName $TaskName"
    Write-Log "    Стоп:    Stop-ScheduledTask -TaskName $TaskName"
    Write-Log "    Старт:   Start-ScheduledTask -TaskName $TaskName"
    Write-Log "    Удалить: .\install_anisette.ps1 -Uninstall"
    Write-Log "═══════════════════════════════════════════════════════════"
}

# ─── Main ──────────────────────────────────────────────────────

function Main {
    if (-not (Test-Admin)) {
        Write-Log "Требуются права администратора. Запустите PowerShell от имени администратора." "ERROR"
        return
    }

    # Handle uninstall
    if ($Uninstall) {
        Uninstall-Anisette
        return
    }

    Write-Log "Установка Anisette-сервера для SideStore..."
    Write-Log "Директория: $InstallDir"
    Write-Log "Порт: $Port"

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Log "Создана директория: $InstallDir" "OK"
    }

    # Step 1: Check Apple Music / iTunes
    Write-Log ""
    Write-Log "Шаг 1: Проверка Apple Music / iTunes..."
    if (-not (Test-AppleMusic)) {
        Install-AppleMusic
        return
    }

    # Step 2: Check anisette server binary
    Write-Log ""
    Write-Log "Шаг 2: Проверка alt_anisette_server.exe..."
    $exePath = Get-AnisetteServer
    if (-not $exePath) {
        return
    }

    # Step 3: Setup scheduled task
    Write-Log ""
    Write-Log "Шаг 3: Настройка автозапуска..."
    Install-AnisetteTask -ExePath $exePath

    # Step 4: Firewall
    Write-Log ""
    Write-Log "Шаг 4: Настройка фаервола..."
    Set-AnisetteFirewall

    # Step 5: Start server
    Write-Log ""
    Write-Log "Шаг 5: Запуск Anisette-сервера..."
    $started = Start-AnisetteServer -ExePath $exePath

    # Step 6: Test
    if ($started) {
        Write-Log ""
        Write-Log "Шаг 6: Проверка..."
        Test-AnisetteEndpoint | Out-Null
    }

    # Summary
    Show-Summary
}

Main
