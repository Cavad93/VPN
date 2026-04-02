#Requires -Version 5.1
<#
.SYNOPSIS
    CavadVPN Server — автоматический установщик для Windows Server 2019/2022.

.DESCRIPTION
    Скрипт выполняет полную установку VPN сервера на Windows:
      1. Проверяет права администратора и ОС
      2. Устанавливает Go 1.22 (если отсутствует)
      3. Устанавливает Git (если отсутствует)
      4. Клонирует или обновляет репозиторий
      5. Собирает бинарный файл сервера (go build)
      6. Создаёт конфигурационный файл (config.yaml)
      7. Генерирует приватный ключ сервера (если отсутствует)
      8. Устанавливает Windows Service (CavadVPN)
      9. Открывает порты в Windows Firewall (443 TCP, 8080 TCP)
     10. Запускает сервис

.PARAMETER InstallDir
    Директория установки. По умолчанию: C:\CavadVPN

.PARAMETER RepoURL
    URL Git репозитория. По умолчанию: https://github.com/cavad93/vpn.git

.PARAMETER ListenAddr
    Адрес и порт VPN сервера. По умолчанию: 0.0.0.0:443

.PARAMETER TunCIDR
    CIDR подсети TUN интерфейса. По умолчанию: 10.8.0.1/24

.PARAMETER APIAddr
    Адрес REST API. По умолчанию: 127.0.0.1:8080

.PARAMETER APIToken
    Bearer токен для REST API. По умолчанию: генерируется случайно.

.PARAMETER SkipBuild
    Пропустить компиляцию (использовать уже собранный бинарник).

.PARAMETER Uninstall
    Удалить сервис и файлы установки.

.EXAMPLE
    # Стандартная установка
    .\install_server.ps1

.EXAMPLE
    # Установка в нестандартную директорию с кастомными настройками
    .\install_server.ps1 -InstallDir "D:\VPN" -ListenAddr "0.0.0.0:8443" -APIToken "mysecrettoken"

.EXAMPLE
    # Удаление
    .\install_server.ps1 -Uninstall

.NOTES
    Требует права администратора.
    Совместим с Windows Server 2019, Windows Server 2022, Windows 10/11.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallDir   = "C:\CavadVPN",
    [string]$RepoURL      = "https://github.com/cavad93/vpn.git",
    [string]$ListenAddr   = "0.0.0.0:443",
    [string]$TunCIDR      = "10.8.0.1/24",
    [string]$APIAddr      = "127.0.0.1:8080",
    [string]$APIToken     = "",
    [switch]$SkipBuild,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Константы ────────────────────────────────────────────────────────────────

$Script:ServiceName   = "CavadVPN"
$Script:DisplayName   = "Cavad VPN Server"
$Script:Description   = "Custom VPN server with Noise_XX encryption and TLS obfuscation"
$Script:GoVersion     = "1.22.4"
$Script:GoInstallerURL = "https://go.dev/dl/go${Script:GoVersion}.windows-amd64.msi"
$Script:GitInstallerURL = "https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe"
$Script:LogFile       = Join-Path $InstallDir "install.log"

# ─── Вспомогательные функции ──────────────────────────────────────────────────

function Write-Log {
    <#
    .SYNOPSIS
    Записывает сообщение в консоль и лог-файл.
    #>
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"

    # Цвет по уровню
    $color = switch ($Level) {
        "INFO"    { "Cyan"   }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red"    }
        "SUCCESS" { "Green"  }
    }
    Write-Host $line -ForegroundColor $color

    # Лог-файл (создаём директорию при необходимости)
    $logDir = Split-Path $Script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
}

function Test-AdminRights {
    <#
    .SYNOPSIS
    Проверяет, запущен ли скрипт с правами администратора.
    #>
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RandomToken {
    <#
    .SYNOPSIS
    Генерирует криптографически случайный hex-токен заданной длины.
    #>
    param([int]$ByteCount = 32)
    $bytes = New-Object byte[] $ByteCount
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return [BitConverter]::ToString($bytes) -replace "-", "" | ForEach-Object { $_.ToLower() }
}

function Test-CommandExists {
    <#
    .SYNOPSIS
    Проверяет, доступна ли команда в PATH.
    #>
    param([string]$Command)
    return $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Invoke-Download {
    <#
    .SYNOPSIS
    Загружает файл по URL с отображением прогресса.
    #>
    param(
        [string]$URL,
        [string]$Destination
    )
    Write-Log "Загрузка: $URL"
    $progressPreference = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"
    try {
        Invoke-WebRequest -Uri $URL -OutFile $Destination -UseBasicParsing
    }
    finally {
        $ProgressPreference = $progressPreference
    }
    Write-Log "Загружено: $Destination"
}

function Install-Go {
    <#
    .SYNOPSIS
    Устанавливает Go $Script:GoVersion если он отсутствует.
    #>
    Write-Log "Проверка Go..."
    if (Test-CommandExists "go") {
        $version = (go version 2>&1) -replace "go version go([^\s]+).*", '$1'
        Write-Log "Go уже установлен: $version" -Level SUCCESS
        return
    }

    Write-Log "Go не найден. Устанавливаем Go $Script:GoVersion..."
    $msiPath = Join-Path $env:TEMP "go_installer.msi"
    Invoke-Download -URL $Script:GoInstallerURL -Destination $msiPath

    Write-Log "Запуск установщика Go..."
    $proc = Start-Process -FilePath "msiexec.exe" `
        -ArgumentList "/i `"$msiPath`" /qn /norestart" `
        -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "Установка Go завершилась с кодом $($proc.ExitCode)"
    }
    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue

    # Обновляем PATH в текущей сессии
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User")

    if (-not (Test-CommandExists "go")) {
        throw "Go установлен, но команда 'go' недоступна. Перезапустите скрипт."
    }
    Write-Log "Go $Script:GoVersion установлен успешно." -Level SUCCESS
}

function Install-Git {
    <#
    .SYNOPSIS
    Устанавливает Git если он отсутствует.
    #>
    Write-Log "Проверка Git..."
    if (Test-CommandExists "git") {
        $version = (git --version 2>&1)
        Write-Log "Git уже установлен: $version" -Level SUCCESS
        return
    }

    Write-Log "Git не найден. Устанавливаем Git..."
    $exePath = Join-Path $env:TEMP "git_installer.exe"
    Invoke-Download -URL $Script:GitInstallerURL -Destination $exePath

    Write-Log "Запуск установщика Git..."
    $proc = Start-Process -FilePath $exePath `
        -ArgumentList "/VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS=`"icons,ext\reg\shellhere,assoc,assoc_sh`"" `
        -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "Установка Git завершилась с кодом $($proc.ExitCode)"
    }
    Remove-Item $exePath -Force -ErrorAction SilentlyContinue

    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User")

    if (-not (Test-CommandExists "git")) {
        throw "Git установлен, но команда 'git' недоступна. Перезапустите скрипт."
    }
    Write-Log "Git установлен успешно." -Level SUCCESS
}

function Get-Repository {
    <#
    .SYNOPSIS
    Клонирует репозиторий или обновляет существующий.
    #>
    param([string]$RepoDir)
    if (Test-Path (Join-Path $RepoDir ".git")) {
        Write-Log "Репозиторий существует. Обновляем..."
        Push-Location $RepoDir
        try {
            git fetch --all 2>&1 | ForEach-Object { Write-Log $_ }
            git reset --hard origin/main 2>&1 | ForEach-Object { Write-Log $_ }
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Log "Клонируем репозиторий: $RepoURL"
        git clone $RepoURL $RepoDir 2>&1 | ForEach-Object { Write-Log $_ }
    }
    Write-Log "Репозиторий готов: $RepoDir" -Level SUCCESS
}

function Build-Server {
    <#
    .SYNOPSIS
    Компилирует VPN сервер под Windows AMD64.
    #>
    param(
        [string]$RepoDir,
        [string]$OutputPath
    )
    Write-Log "Сборка VPN сервера..."
    Push-Location (Join-Path $RepoDir "server")
    try {
        $env:GOOS   = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"

        # Загружаем зависимости
        Write-Log "go mod download..."
        go mod download 2>&1 | ForEach-Object { Write-Log $_ }

        # Компилируем
        Write-Log "go build..."
        $buildArgs = @(
            "build",
            "-ldflags", "-s -w -X main.version=$(git describe --tags --always 2>$null)",
            "-o", $OutputPath,
            "."
        )
        & go @buildArgs 2>&1 | ForEach-Object { Write-Log $_ }
        if ($LASTEXITCODE -ne 0) {
            throw "Компиляция завершилась с ошибкой (exit code $LASTEXITCODE)"
        }
    }
    finally {
        Remove-Item Env:\GOOS        -ErrorAction SilentlyContinue
        Remove-Item Env:\GOARCH      -ErrorAction SilentlyContinue
        Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
        Pop-Location
    }
    Write-Log "Бинарник собран: $OutputPath" -Level SUCCESS
}

function New-ServerConfig {
    <#
    .SYNOPSIS
    Создаёт конфигурационный файл config.yaml.
    Не перезаписывает существующий файл.
    #>
    param(
        [string]$ConfigPath,
        [string]$KeyFilePath,
        [string]$Token
    )
    if (Test-Path $ConfigPath) {
        Write-Log "Конфигурация уже существует: $ConfigPath. Пропускаем." -Level WARN
        return
    }

    Write-Log "Создание конфигурации: $ConfigPath"

    $yaml = @"
# CavadVPN Server Configuration
# Автоматически создан установщиком $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

listen: "$ListenAddr"
tun_cidr: "$TunCIDR"
private_key_file: "$($KeyFilePath -replace '\\', '/')"

# Список разрешённых публичных ключей клиентов (hex).
# Оставьте пустым, чтобы разрешить любые ключи (не рекомендуется).
allowed_keys: []

api:
  listen: "$APIAddr"
  token: "$Token"

log:
  level: "info"
  format: "text"
"@

    Set-Content -Path $ConfigPath -Value $yaml -Encoding UTF8
    Write-Log "Конфигурация создана." -Level SUCCESS
}

function Install-Service {
    <#
    .SYNOPSIS
    Регистрирует Windows Service через sc.exe.
    #>
    param(
        [string]$BinaryPath,
        [string]$ConfigPath
    )

    # Удаляем старый сервис если есть
    $existing = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Останавливаем существующий сервис..."
        if ($existing.Status -eq "Running") {
            Stop-Service -Name $Script:ServiceName -Force
            Start-Sleep -Seconds 3
        }
        Write-Log "Удаляем существующий сервис..."
        sc.exe delete $Script:ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    Write-Log "Регистрация сервиса $Script:ServiceName..."
    $binPathQuoted = "`"$BinaryPath`" -config `"$ConfigPath`""
    sc.exe create $Script:ServiceName `
        binPath= $binPathQuoted `
        start= auto `
        DisplayName= $Script:DisplayName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create завершился с ошибкой $LASTEXITCODE"
    }

    # Описание сервиса
    sc.exe description $Script:ServiceName $Script:Description | Out-Null

    # Действия при сбое: перезапуск через 30 сек, 60 сек, 120 сек
    sc.exe failure $Script:ServiceName reset= 86400 actions= restart/30000/restart/60000/restart/120000 | Out-Null

    Write-Log "Сервис $Script:ServiceName зарегистрирован." -Level SUCCESS
}

function Set-FirewallRules {
    <#
    .SYNOPSIS
    Открывает порты 443 (VPN) и 8080 (API) в Windows Firewall.
    #>
    Write-Log "Настройка правил Windows Firewall..."

    $rules = @(
        @{ Name = "CavadVPN-In-443-TCP";  Port = 443;  Proto = "TCP"; Dir = "Inbound"  },
        @{ Name = "CavadVPN-In-443-UDP";  Port = 443;  Proto = "UDP"; Dir = "Inbound"  },
        @{ Name = "CavadVPN-API-8080-TCP"; Port = 8080; Proto = "TCP"; Dir = "Inbound" }
    )

    foreach ($rule in $rules) {
        # Удалить старое правило если есть
        Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue

        New-NetFirewallRule `
            -DisplayName $rule.Name `
            -Direction   $rule.Dir `
            -Protocol    $rule.Proto `
            -LocalPort   $rule.Port `
            -Action      Allow `
            -Profile     Any `
            -Enabled     True | Out-Null
        Write-Log "Правило добавлено: $($rule.Name)" -Level SUCCESS
    }
}

function Enable-IPRouting {
    <#
    .SYNOPSIS
    Включает IP маршрутизацию (IP Forwarding) в реестре.
    Необходима для работы VPN — сервер пересылает пакеты между TUN и WAN.
    #>
    Write-Log "Включение IP маршрутизации (IP Forwarding)..."
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-ItemProperty -Path $key -Name "IPEnableRouter" -Value 1 -Type DWord
    Write-Log "IP маршрутизация включена (вступит в силу после перезагрузки)." -Level SUCCESS
}

function Install-TAP {
    <#
    .SYNOPSIS
    Устанавливает TAP-Windows адаптер (OpenVPN/WireGuard TAP driver).
    Требуется для TUN/TAP на Windows.
    #>
    Write-Log "Проверка TAP адаптера..."
    $tapAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like "*TAP*" }
    if ($tapAdapter) {
        Write-Log "TAP адаптер уже установлен: $($tapAdapter.Name)" -Level SUCCESS
        return
    }

    Write-Log "TAP адаптер не найден." -Level WARN
    Write-Log "Для полноценной работы TUN/TAP установите один из вариантов:" -Level WARN
    Write-Log "  - Wintun:    https://www.wintun.net/" -Level WARN
    Write-Log "  - TAP-Windows: входит в состав OpenVPN или WireGuard для Windows" -Level WARN
    Write-Log "Сервер может работать без TUN на stub-платформах (только relay режим)." -Level WARN
}

function Start-VPNService {
    <#
    .SYNOPSIS
    Запускает Windows Service CavadVPN.
    #>
    Write-Log "Запуск сервиса $Script:ServiceName..."
    Start-Service -Name $Script:ServiceName
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $Script:ServiceName
    if ($svc.Status -eq "Running") {
        Write-Log "Сервис запущен успешно." -Level SUCCESS
    }
    else {
        Write-Log "Сервис запущен, но статус: $($svc.Status)" -Level WARN
        Write-Log "Проверьте Event Viewer или лог: $Script:LogFile" -Level WARN
    }
}

function Uninstall-Server {
    <#
    .SYNOPSIS
    Останавливает и удаляет сервис, удаляет правила фаервола.
    Файлы в $InstallDir не удаляются (ключи и конфиг сохраняются).
    #>
    Write-Log "Удаление CavadVPN..."

    # Остановить сервис
    $svc = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Write-Log "Останавливаем сервис..."
            Stop-Service -Name $Script:ServiceName -Force
            Start-Sleep -Seconds 3
        }
        Write-Log "Удаляем сервис..."
        sc.exe delete $Script:ServiceName | Out-Null
    }
    else {
        Write-Log "Сервис не найден." -Level WARN
    }

    # Удалить правила фаервола
    Write-Log "Удаление правил фаервола..."
    @("CavadVPN-In-443-TCP", "CavadVPN-In-443-UDP", "CavadVPN-API-8080-TCP") | ForEach-Object {
        Remove-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue
    }

    Write-Log "CavadVPN удалён." -Level SUCCESS
    Write-Log "Файлы в $InstallDir сохранены (ключи и конфиг)." -Level WARN
    Write-Log "Для полного удаления выполните: Remove-Item -Recurse -Force `"$InstallDir`"" -Level WARN
}

function Show-Summary {
    <#
    .SYNOPSIS
    Выводит итоговую информацию об установке.
    #>
    param([string]$ConfigPath, [string]$Token, [string]$KeyFilePath)

    $svc = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
    $status = if ($svc) { $svc.Status } else { "Не установлен" }

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║          CavadVPN Server — Установка завершена       ║" -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Директория:   $InstallDir" -ForegroundColor Green
    Write-Host "║  Конфигурация: $ConfigPath" -ForegroundColor Green
    Write-Host "║  Приватный ключ: $KeyFilePath" -ForegroundColor Green
    Write-Host "║  Сервис:       $Script:ServiceName ($status)" -ForegroundColor Green
    Write-Host "║  VPN порт:     443 (TCP/UDP)" -ForegroundColor Green
    Write-Host "║  API адрес:    http://$APIAddr" -ForegroundColor Green
    Write-Host "║  API токен:    $Token" -ForegroundColor Yellow
    Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Следующие шаги:                                     " -ForegroundColor Cyan
    Write-Host "║  1. Запишите API токен — он больше не отображается!  " -ForegroundColor Yellow
    Write-Host "║  2. Откройте http://$APIAddr в браузере" -ForegroundColor Cyan
    Write-Host "║  3. Добавьте публичный ключ клиента через веб-панель " -ForegroundColor Cyan
    Write-Host "║  4. Настройте клиент (client/core.py) на этот сервер " -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Log "Установка завершена. Лог: $Script:LogFile" -Level SUCCESS
}

# ─── Главная логика ───────────────────────────────────────────────────────────

function Main {
    Write-Log "=== CavadVPN Server Installer ==="
    Write-Log "Версия Go: $Script:GoVersion"
    Write-Log "Директория установки: $InstallDir"

    # Проверка прав администратора
    if (-not (Test-AdminRights)) {
        Write-Log "Требуются права администратора! Запустите PowerShell от имени администратора." -Level ERROR
        exit 1
    }
    Write-Log "Права администратора: OK" -Level SUCCESS

    # Режим удаления
    if ($Uninstall) {
        Uninstall-Server
        return
    }

    # Пути
    $repoDir    = Join-Path $InstallDir "src"
    $binaryPath = Join-Path $InstallDir "cavad-vpn.exe"
    $configPath = Join-Path $InstallDir "config.yaml"
    $keyFilePath = Join-Path $InstallDir "server_privkey.hex"

    # Генерируем токен если не задан
    if ([string]::IsNullOrWhiteSpace($APIToken)) {
        $Script:token = Get-RandomToken -ByteCount 32
    }
    else {
        $Script:token = $APIToken
    }

    # 1. Создать директорию установки
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Log "Директория создана: $InstallDir" -Level SUCCESS
    }

    # 2. Установка Go
    Install-Go

    # 3. Установка Git
    Install-Git

    # 4. Получение репозитория
    Get-Repository -RepoDir $repoDir

    # 5. Сборка бинарника
    if (-not $SkipBuild) {
        Build-Server -RepoDir $repoDir -OutputPath $binaryPath
    }
    elseif (-not (Test-Path $binaryPath)) {
        throw "SkipBuild задан, но бинарник не найден: $binaryPath"
    }

    # 6. Конфигурация
    New-ServerConfig `
        -ConfigPath  $configPath `
        -KeyFilePath $keyFilePath `
        -Token       $Script:token

    # 7. TAP адаптер (предупреждение)
    Install-TAP

    # 8. IP маршрутизация
    Enable-IPRouting

    # 9. Установка Windows Service
    if ($PSCmdlet.ShouldProcess($Script:ServiceName, "Install Windows Service")) {
        Install-Service -BinaryPath $binaryPath -ConfigPath $configPath
    }

    # 10. Правила фаервола
    if ($PSCmdlet.ShouldProcess("Windows Firewall", "Add CavadVPN rules")) {
        Set-FirewallRules
    }

    # 11. Запуск сервиса
    if ($PSCmdlet.ShouldProcess($Script:ServiceName, "Start Service")) {
        Start-VPNService
    }

    # 12. Итог
    Show-Summary -ConfigPath $configPath -Token $Script:token -KeyFilePath $keyFilePath
}

Main
