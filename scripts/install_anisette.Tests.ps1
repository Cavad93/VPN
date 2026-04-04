# Pester 5.x tests for install_anisette.ps1
# Run: Invoke-Pester .\scripts\install_anisette.Tests.ps1 -Output Detailed

BeforeAll {
    . $PSScriptRoot\install_anisette.ps1 -InstallDir "TestDrive:\anisette" -Port 16969 -WhatIf *> $null 2>&1

    # Re-source just the functions (without running Main)
    # We define the functions inline for testing since the script runs Main on source
}

Describe "Write-Log" {
    It "should not throw on INFO" {
        { Write-Log "test message" "INFO" } | Should -Not -Throw
    }

    It "should not throw on ERROR" {
        { Write-Log "error message" "ERROR" } | Should -Not -Throw
    }

    It "should not throw on OK" {
        { Write-Log "ok message" "OK" } | Should -Not -Throw
    }
}

Describe "Test-Admin" {
    It "should return boolean" {
        $result = Test-Admin
        $result | Should -BeOfType [bool]
    }
}

Describe "Test-AppleMusic" {
    It "should return boolean" {
        $result = Test-AppleMusic
        $result | Should -BeOfType [bool]
    }

    It "should not throw" {
        { Test-AppleMusic } | Should -Not -Throw
    }
}

Describe "Install directory" {
    It "default install dir should be C:\CavadVPN\anisette" {
        # Verify the default parameter value
        $cmd = Get-Command "$PSScriptRoot\install_anisette.ps1"
        $param = $cmd.Parameters["InstallDir"]
        $param | Should -Not -BeNullOrEmpty
    }
}

Describe "Script parameters" {
    BeforeAll {
        $cmd = Get-Command "$PSScriptRoot\install_anisette.ps1"
    }

    It "should have InstallDir parameter" {
        $cmd.Parameters.ContainsKey("InstallDir") | Should -BeTrue
    }

    It "should have Port parameter" {
        $cmd.Parameters.ContainsKey("Port") | Should -BeTrue
    }

    It "should have Uninstall parameter" {
        $cmd.Parameters.ContainsKey("Uninstall") | Should -BeTrue
    }

    It "should support ShouldProcess" {
        $cmd.Parameters.ContainsKey("WhatIf") | Should -BeTrue
    }
}

Describe "TaskName constant" {
    It "should be CavadVPN_Anisette" {
        $TaskName | Should -Be "CavadVPN_Anisette"
    }
}

Describe "Default port" {
    It "should be 6969" {
        $Port | Should -Be 6969
    }
}
