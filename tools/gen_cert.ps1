<#
.SYNOPSIS
    Generates a self-signed TLS certificate for VLESS+WS+TLS.
.EXAMPLE
    .\gen_cert.ps1 -OutputDir C:\CavadVPN
#>

param(
    [string]$OutputDir = "C:\CavadVPN",
    [string]$Domain = "CavadVPN",
    [int]$Days = 3650
)

$certPath = Join-Path $OutputDir "cert.pem"
$keyPath  = Join-Path $OutputDir "key.pem"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "Generating certificate..."

$cert = New-SelfSignedCertificate `
    -DnsName $Domain `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddDays($Days) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -KeyExportPolicy Exportable

$thumbprint = $cert.Thumbprint
Write-Host "  Thumbprint: $thumbprint"

# --- Export certificate (public) as PEM ---
$certB64 = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
[System.IO.File]::WriteAllText($certPath, "-----BEGIN CERTIFICATE-----`r`n$certB64`r`n-----END CERTIFICATE-----`r`n")

# --- Export private key via PFX round-trip ---
# This works on all PowerShell 5.1 / Windows Server 2019 systems.
$pfxPath = Join-Path $OutputDir "temp_export.pfx"
$pfxPass = "CavadVPN_temp_$(Get-Random)"
$secPass = ConvertTo-SecureString -String $pfxPass -Force -AsPlainText

Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumbprint" -FilePath $pfxPath -Password $secPass | Out-Null

# Re-import PFX with Exportable flag to get access to CNG key
$pfxBytes = [System.IO.File]::ReadAllBytes($pfxPath)
$pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $pfxBytes, $pfxPass,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
)

$exported = $false

# Try 1: CNG path (RSACng with accessible .Key)
try {
    $rsa = $pfxCert.PrivateKey
    if ($rsa -and $rsa.Key) {
        $pkcs8 = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $keyB64 = [Convert]::ToBase64String($pkcs8, [Base64FormattingOptions]::InsertLineBreaks)
        [System.IO.File]::WriteAllText($keyPath, "-----BEGIN PRIVATE KEY-----`r`n$keyB64`r`n-----END PRIVATE KEY-----`r`n")
        $exported = $true
        Write-Host "  Key exported via CNG"
    }
} catch {
    Write-Host "  CNG path skipped: $_" -ForegroundColor Yellow
}

# Try 2: RSACryptoServiceProvider path (CAPI)
if (-not $exported) {
    try {
        $rsa = $pfxCert.PrivateKey
        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $cspBlob = $rsa.ExportCspBlob($true)
            # Convert CSP blob to RSA parameters, then build PKCS#1 DER
            $rsaParams = $rsa.ExportParameters($true)
            # Use RSACryptoServiceProvider → convert to RSACng for PKCS8 export
            $rsaCng = New-Object System.Security.Cryptography.RSACng
            $rsaCng.ImportParameters($rsaParams)
            $pkcs8 = $rsaCng.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            $keyB64 = [Convert]::ToBase64String($pkcs8, [Base64FormattingOptions]::InsertLineBreaks)
            [System.IO.File]::WriteAllText($keyPath, "-----BEGIN PRIVATE KEY-----`r`n$keyB64`r`n-----END PRIVATE KEY-----`r`n")
            $exported = $true
            Write-Host "  Key exported via CAPI→CNG"
        }
    } catch {
        Write-Host "  CAPI path skipped: $_" -ForegroundColor Yellow
    }
}

# Try 3: Direct RSA parameters → manual PKCS#1 PEM
if (-not $exported) {
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfxCert)
        if ($rsa) {
            $rsaNew = New-Object System.Security.Cryptography.RSACng
            $rsaNew.ImportParameters($rsa.ExportParameters($true))
            $pkcs8 = $rsaNew.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            $keyB64 = [Convert]::ToBase64String($pkcs8, [Base64FormattingOptions]::InsertLineBreaks)
            [System.IO.File]::WriteAllText($keyPath, "-----BEGIN PRIVATE KEY-----`r`n$keyB64`r`n-----END PRIVATE KEY-----`r`n")
            $exported = $true
            Write-Host "  Key exported via GetRSAPrivateKey→CNG"
        }
    } catch {
        Write-Host "  Extension method path skipped: $_" -ForegroundColor Yellow
    }
}

# Clean up
$pfxCert.Dispose()
Remove-Item $pfxPath -ErrorAction SilentlyContinue
Remove-Item "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue

# Verify
$certSize = if (Test-Path $certPath) { (Get-Item $certPath).Length } else { 0 }
$keySize  = if (Test-Path $keyPath)  { (Get-Item $keyPath).Length }  else { 0 }

if ($certSize -gt 100 -and $keySize -gt 100) {
    Write-Host ""
    Write-Host "OK: cert=$certPath ($certSize B), key=$keyPath ($keySize B)" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "FAILED (cert=$certSize B, key=$keySize B)" -ForegroundColor Red
    Write-Host "Install OpenSSL: winget install ShiningLight.OpenSSL" -ForegroundColor Yellow
    exit 1
}
