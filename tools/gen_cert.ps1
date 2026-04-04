<#
.SYNOPSIS
    Generates a self-signed TLS certificate for VLESS+WS+TLS.

.DESCRIPTION
    Creates cert.pem and key.pem in the specified directory.
    Works on Windows Server 2019+ with PowerShell 5.1 (no OpenSSL needed).

.EXAMPLE
    .\gen_cert.ps1 -OutputDir C:\CavadVPN -Domain vpn.example.com
    .\gen_cert.ps1   # uses defaults: C:\CavadVPN, CN=CavadVPN
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

# Try OpenSSL first (cleaner output)
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    Write-Host "Using OpenSSL..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 `
        -keyout $keyPath -out $certPath `
        -days $Days -nodes `
        -subj "/CN=$Domain" `
        -addext "subjectAltName=DNS:$Domain" 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0 -and (Test-Path $keyPath) -and (Get-Item $keyPath).Length -gt 100) {
        Write-Host "  cert: $certPath"
        Write-Host "  key:  $keyPath"
        exit 0
    }
    Write-Host "OpenSSL failed, falling back to PowerShell..."
}

# Pure PowerShell path (Windows Server 2019+, PowerShell 5.1)
Write-Host "Generating certificate with PowerShell..."

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
$certDer = $cert.RawData
$certB64 = [Convert]::ToBase64String($certDer, [Base64FormattingOptions]::InsertLineBreaks)
$certPem = "-----BEGIN CERTIFICATE-----`r`n$certB64`r`n-----END CERTIFICATE-----`r`n"
[System.IO.File]::WriteAllText($certPath, $certPem)

# --- Export private key as PEM ---
# On PowerShell 5.1 (.NET Framework), PrivateKey is RSACng.
# RSACng.Key (CngKey) supports Export(Pkcs8PrivateBlob).
$rsa = $cert.PrivateKey
$keyExported = $false

try {
    $pkcs8 = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
    $keyB64 = [Convert]::ToBase64String($pkcs8, [Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`r`n$keyB64`r`n-----END PRIVATE KEY-----`r`n"
    [System.IO.File]::WriteAllText($keyPath, $keyPem)
    $keyExported = $true
} catch {
    Write-Host "  CNG export failed: $_" -ForegroundColor Yellow
}

# Clean up cert from store
Remove-Item "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue

# Verify
$certSize = (Get-Item $certPath -ErrorAction SilentlyContinue).Length
$keySize  = (Get-Item $keyPath -ErrorAction SilentlyContinue).Length

if ($certSize -gt 100 -and $keySize -gt 100) {
    Write-Host ""
    Write-Host "Certificate generated successfully:" -ForegroundColor Green
    Write-Host "  cert: $certPath ($certSize bytes)"
    Write-Host "  key:  $keyPath ($keySize bytes)"
} else {
    Write-Host ""
    Write-Host "ERROR: Generation failed (cert=$certSize bytes, key=$keySize bytes)" -ForegroundColor Red
    Write-Host "  Try installing OpenSSL: winget install OpenSSL" -ForegroundColor Yellow
    exit 1
}
