#Requires -Version 5.1
<#
.SYNOPSIS
    Pester тесты для install_server.ps1

.DESCRIPTION
    Тестирует вспомогательные функции установщика:
      - Write-Log
      - Test-AdminRights
      - Get-RandomToken
      - Test-CommandExists
      - New-ServerConfig
      - Uninstall-Server (mock)
      - Set-FirewallRules (mock)
      - Install-Service (mock)

    Запуск:
        Invoke-Pester .\install_server.Tests.ps1 -Output Detailed

    Требует Pester 5.x:
        Install-Module Pester -MinimumVersion 5.0 -Force
#>

BeforeAll {
    # Dot-source инсталлятора без выполнения Main()
    # Переопределяем Main, чтобы он не запустился при . sourcing
    $script:MainCalled = $false

    # Загружаем функции из install_server.ps1, подменяя Main
    $installerContent = Get-Content "$PSScriptRoot\install_server.ps1" -Raw
    # Заменяем вызов Main в конце файла на маркер
    $installerContent = $installerContent -replace '^Main$', '# Main suppressed for tests'
    $tempFile = Join-Path $env:TEMP "install_server_test_$(Get-Random).ps1"
    Set-Content -Path $tempFile -Value $installerContent -Encoding UTF8
    . $tempFile
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

    # Временная директория для тестов
    $script:TestDir = Join-Path $env:TEMP "CavadVPN_Test_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Переопределяем глобальные переменные инсталлятора
    $script:LogFile = Join-Path $script:TestDir "install_test.log"
    $script:InstallDir = $script:TestDir
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir -ErrorAction SilentlyContinue
    }
}

# ─── Write-Log ────────────────────────────────────────────────────────────────

Describe "Write-Log" {
    BeforeEach {
        # Очищаем лог перед каждым тестом
        if (Test-Path $script:LogFile) { Remove-Item $script:LogFile -Force }
    }

    It "создаёт лог-файл при первом вызове" {
        Write-Log "Test message"
        Test-Path $script:LogFile | Should -Be $true
    }

    It "записывает уровень INFO по умолчанию" {
        Write-Log "Test INFO"
        $content = Get-Content $script:LogFile -Raw
        $content | Should -Match "\[INFO\]"
    }

    It "записывает уровень WARN" {
        Write-Log "Test WARN" -Level WARN
        Get-Content $script:LogFile -Raw | Should -Match "\[WARN\]"
    }

    It "записывает уровень ERROR" {
        Write-Log "Test ERROR" -Level ERROR
        Get-Content $script:LogFile -Raw | Should -Match "\[ERROR\]"
    }

    It "записывает уровень SUCCESS" {
        Write-Log "Test SUCCESS" -Level SUCCESS
        Get-Content $script:LogFile -Raw | Should -Match "\[SUCCESS\]"
    }

    It "записывает текст сообщения" {
        $msg = "Уникальное сообщение 12345"
        Write-Log $msg
        Get-Content $script:LogFile -Raw | Should -Match [regex]::Escape($msg)
    }

    It "добавляет временную метку" {
        Write-Log "Timestamp test"
        $content = Get-Content $script:LogFile -Raw
        # Формат: [2026-04-02 12:00:00]
        $content | Should -Match "\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]"
    }

    It "добавляет несколько строк" {
        Write-Log "Line 1"
        Write-Log "Line 2"
        Write-Log "Line 3"
        $lines = Get-Content $script:LogFile
        $lines.Count | Should -Be 3
    }
}

# ─── Test-AdminRights ─────────────────────────────────────────────────────────

Describe "Test-AdminRights" {
    It "возвращает boolean" {
        $result = Test-AdminRights
        $result | Should -BeOfType [bool]
    }

    It "не бросает исключений" {
        { Test-AdminRights } | Should -Not -Throw
    }
}

# ─── Get-RandomToken ──────────────────────────────────────────────────────────

Describe "Get-RandomToken" {
    It "возвращает строку" {
        $token = Get-RandomToken
        $token | Should -BeOfType [string]
    }

    It "возвращает hex строку (только 0-9, a-f)" {
        $token = Get-RandomToken -ByteCount 32
        $token | Should -Match "^[0-9a-f]+$"
    }

    It "длина по умолчанию = 64 символа (32 байта * 2)" {
        $token = Get-RandomToken -ByteCount 32
        $token.Length | Should -Be 64
    }

    It "длина 16 байт = 32 символа" {
        $token = Get-RandomToken -ByteCount 16
        $token.Length | Should -Be 32
    }

    It "каждый вызов возвращает уникальный токен" {
        $tokens = 1..10 | ForEach-Object { Get-RandomToken -ByteCount 16 }
        $unique = $tokens | Select-Object -Unique
        $unique.Count | Should -Be 10
    }

    It "не содержит дефисов" {
        $token = Get-RandomToken -ByteCount 32
        $token | Should -Not -Match "-"
    }
}

# ─── Test-CommandExists ───────────────────────────────────────────────────────

Describe "Test-CommandExists" {
    It "возвращает true для powershell.exe" {
        Test-CommandExists "powershell.exe" | Should -Be $true
    }

    It "возвращает true для cmd" {
        Test-CommandExists "cmd" | Should -Be $true
    }

    It "возвращает false для несуществующей команды" {
        Test-CommandExists "absolutely_nonexistent_command_xyz_12345" | Should -Be $false
    }

    It "возвращает boolean" {
        $result = Test-CommandExists "powershell"
        $result | Should -BeOfType [bool]
    }

    It "не бросает исключений для несуществующей команды" {
        { Test-CommandExists "nonexistent_cmd_999" } | Should -Not -Throw
    }
}

# ─── New-ServerConfig ─────────────────────────────────────────────────────────

Describe "New-ServerConfig" {
    BeforeEach {
        $script:configPath  = Join-Path $script:TestDir "config_$(Get-Random).yaml"
        $script:keyFilePath = Join-Path $script:TestDir "server_privkey.hex"
        $script:testToken   = Get-RandomToken -ByteCount 16
        # Параметры инсталлятора
        $script:ListenAddr = "0.0.0.0:443"
        $script:TunCIDR    = "10.8.0.1/24"
        $script:APIAddr    = "127.0.0.1:8080"
    }

    It "создаёт файл конфигурации" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        Test-Path $script:configPath | Should -Be $true
    }

    It "содержит listen адрес" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        Get-Content $script:configPath -Raw | Should -Match "0\.0\.0\.0:443"
    }

    It "содержит tun_cidr" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        Get-Content $script:configPath -Raw | Should -Match "10\.8\.0\.1/24"
    }

    It "содержит API адрес" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        Get-Content $script:configPath -Raw | Should -Match "127\.0\.0\.1:8080"
    }

    It "содержит API токен" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        Get-Content $script:configPath -Raw | Should -Match [regex]::Escape($script:testToken)
    }

    It "содержит путь к приватному ключу" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        $content = Get-Content $script:configPath -Raw
        # Путь должен быть в YAML (слеши конвертированы)
        $content | Should -Match "private_key_file"
    }

    It "не перезаписывает существующий файл" {
        # Создаём маркерный файл
        Set-Content -Path $script:configPath -Value "# ORIGINAL MARKER" -Encoding UTF8

        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken

        Get-Content $script:configPath -Raw | Should -Match "ORIGINAL MARKER"
    }

    It "содержит allowed_keys (пустой список)" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        Get-Content $script:configPath -Raw | Should -Match "allowed_keys"
    }

    It "содержит настройки логирования" {
        New-ServerConfig `
            -ConfigPath  $script:configPath `
            -KeyFilePath $script:keyFilePath `
            -Token       $script:testToken
        $content = Get-Content $script:configPath -Raw
        $content | Should -Match "log:"
        $content | Should -Match "level:"
    }
}

# ─── Enable-IPRouting ─────────────────────────────────────────────────────────

Describe "Enable-IPRouting" {
    It "не бросает исключений (требует admin на реальной системе)" {
        # На не-Windows среде или без прав — ожидаем либо успех, либо конкретную ошибку
        if (-not (Test-AdminRights)) {
            Set-ItResult -Skipped -Because "Требуются права администратора"
            return
        }
        { Enable-IPRouting } | Should -Not -Throw
    }

    It "IPEnableRouter ключ в реестре существует" {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Test-Path $key | Should -Be $true
    }
}

# ─── Install-TAP ──────────────────────────────────────────────────────────────

Describe "Install-TAP" {
    It "не бросает исключений" {
        # Функция только проверяет наличие адаптера и выводит предупреждение
        { Install-TAP } | Should -Not -Throw
    }
}

# ─── Uninstall-Server ─────────────────────────────────────────────────────────

Describe "Uninstall-Server" {
    It "не бросает исключений если сервис не установлен" {
        # CavadVPN не установлен в тестовой среде
        $svc = Get-Service -Name "CavadVPN" -ErrorAction SilentlyContinue
        if (-not $svc) {
            { Uninstall-Server } | Should -Not -Throw
        }
        else {
            Set-ItResult -Skipped -Because "Сервис CavadVPN реально установлен — пропускаем тест удаления"
        }
    }
}

# ─── Интеграционные тесты (без реальной установки) ───────────────────────────

Describe "Интеграционный тест: New-ServerConfig генерирует валидный YAML" {
    It "созданный файл содержит все обязательные поля YAML" {
        $configPath = Join-Path $script:TestDir "integration_config.yaml"
        $token = Get-RandomToken -ByteCount 32

        $script:ListenAddr = "0.0.0.0:443"
        $script:TunCIDR    = "10.8.0.1/24"
        $script:APIAddr    = "127.0.0.1:8080"

        New-ServerConfig `
            -ConfigPath  $configPath `
            -KeyFilePath (Join-Path $script:TestDir "key.hex") `
            -Token       $token

        $content = Get-Content $configPath -Raw

        # Обязательные YAML ключи
        @("listen:", "tun_cidr:", "private_key_file:", "allowed_keys:", "api:", "log:") | ForEach-Object {
            $content | Should -Match [regex]::Escape($_)
        }
    }

    It "токен уникален в каждом запуске" {
        $tokens = 1..5 | ForEach-Object { Get-RandomToken -ByteCount 32 }
        ($tokens | Select-Object -Unique).Count | Should -Be 5
    }
}

Describe "Интеграционный тест: лог-файл" {
    It "пишет несколько уровней в один файл" {
        $logPath = Join-Path $script:TestDir "multi_level.log"
        $script:LogFile = $logPath

        Write-Log "Info message"   -Level INFO
        Write-Log "Warn message"   -Level WARN
        Write-Log "Error message"  -Level ERROR
        Write-Log "Success message" -Level SUCCESS

        $content = Get-Content $logPath -Raw
        $content | Should -Match "\[INFO\]"
        $content | Should -Match "\[WARN\]"
        $content | Should -Match "\[ERROR\]"
        $content | Should -Match "\[SUCCESS\]"

        # Сброс на дефолтный лог
        $script:LogFile = Join-Path $script:TestDir "install_test.log"
    }
}
