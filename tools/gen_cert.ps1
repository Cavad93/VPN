<#
.SYNOPSIS
    Generates a self-signed TLS certificate for VLESS+WS+TLS.

.DESCRIPTION
    Creates cert.pem and key.pem in the specified directory.
    Uses OpenSSL if available, otherwise PowerShell's New-SelfSignedCertificate.

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

# Fallback: PowerShell (Windows only)
Write-Host "Using PowerShell New-SelfSignedCertificate..."
$cert = New-SelfSignedCertificate `
    -DnsName $Domain `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddDays($Days) `
    -KeyAlgorithm ECDSA_nistP256 `
    -KeyExportPolicy Exportable

# Export to PFX then convert to PEM
$pfxPath = Join-Path $OutputDir "temp.pfx"
$password = ConvertTo-SecureString -String "temp" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password | Out-Null

# Convert PFX → PEM using certutil or openssl
openssl pkcs12 -in $pfxPath -out $certPath -clcerts -nokeys -password pass:temp 2>$null
openssl pkcs12 -in $pfxPath -out $keyPath -nocerts -nodes -password pass:temp 2>$null

Remove-Item $pfxPath -ErrorAction SilentlyContinue
# Clean up cert store
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue

Write-Host "Certificate generated:"
Write-Host "  cert: $certPath"
Write-Host "  key:  $keyPath"
