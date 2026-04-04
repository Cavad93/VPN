<#
.SYNOPSIS
    Generates a self-signed TLS certificate for VLESS+WS+TLS.

.DESCRIPTION
    Creates cert.pem and key.pem in the specified directory.
    Uses OpenSSL if available, otherwise pure PowerShell + certutil.

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

# Try OpenSSL first (cleaner PEM output)
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    Write-Host "Using OpenSSL to generate certificate..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 `
        -keyout $keyPath -out $certPath `
        -days $Days -nodes `
        -subj "/CN=$Domain" `
        -addext "subjectAltName=DNS:$Domain" 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Certificate generated:"
        Write-Host "  cert: $certPath"
        Write-Host "  key:  $keyPath"
        exit 0
    }
    Write-Host "OpenSSL failed, falling back to PowerShell..."
}

# Fallback: pure PowerShell + certutil (no OpenSSL needed)
Write-Host "Using PowerShell New-SelfSignedCertificate..."

$cert = New-SelfSignedCertificate `
    -DnsName $Domain `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddDays($Days) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -KeyExportPolicy Exportable

$thumbprint = $cert.Thumbprint
Write-Host "Created certificate: $thumbprint"

# Export to PFX
$pfxPath = Join-Path $OutputDir "temp.pfx"
$password = ConvertTo-SecureString -String "temppass123" -Force -AsPlainText
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumbprint" -FilePath $pfxPath -Password $password | Out-Null

# Convert PFX → PEM using certutil (built into Windows)
# Step 1: Extract certificate (public part)
$derCertPath = Join-Path $OutputDir "temp_cert.der"
Export-Certificate -Cert "Cert:\CurrentUser\My\$thumbprint" -FilePath $derCertPath -Type CERT | Out-Null

# Convert DER → Base64 PEM
$certBytes = [System.IO.File]::ReadAllBytes($derCertPath)
$certBase64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
$certPem = "-----BEGIN CERTIFICATE-----`r`n$certBase64`r`n-----END CERTIFICATE-----`r`n"
[System.IO.File]::WriteAllText($certPath, $certPem)

# Step 2: Extract private key from PFX using .NET
$pfxCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$pfxCollection.Import($pfxPath, "temppass123", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

$privKey = $pfxCollection[0].PrivateKey
if ($null -eq $privKey) {
    # .NET Core / 5+ path
    $privKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfxCollection[0])
}

if ($privKey) {
    $keyBytes = $privKey.ExportRSAPrivateKey()
    $keyBase64 = [Convert]::ToBase64String($keyBytes, [Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN RSA PRIVATE KEY-----`r`n$keyBase64`r`n-----END RSA PRIVATE KEY-----`r`n"
    [System.IO.File]::WriteAllText($keyPath, $keyPem)
} else {
    # Last resort: export PKCS8
    $keyBytes = $pfxCollection[0].GetRSAPrivateKey().ExportPkcs8PrivateKey()
    $keyBase64 = [Convert]::ToBase64String($keyBytes, [Base64FormattingOptions]::InsertLineBreaks)
    $keyPem = "-----BEGIN PRIVATE KEY-----`r`n$keyBase64`r`n-----END PRIVATE KEY-----`r`n"
    [System.IO.File]::WriteAllText($keyPath, $keyPem)
}

# Clean up temp files and cert store
Remove-Item $pfxPath -ErrorAction SilentlyContinue
Remove-Item $derCertPath -ErrorAction SilentlyContinue
Remove-Item "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue

# Verify files exist and have content
$certSize = (Get-Item $certPath -ErrorAction SilentlyContinue).Length
$keySize  = (Get-Item $keyPath -ErrorAction SilentlyContinue).Length

if ($certSize -gt 0 -and $keySize -gt 0) {
    Write-Host ""
    Write-Host "Certificate generated successfully:"
    Write-Host "  cert: $certPath ($certSize bytes)"
    Write-Host "  key:  $keyPath ($keySize bytes)"
} else {
    Write-Host "ERROR: Certificate generation failed!" -ForegroundColor Red
    exit 1
}
