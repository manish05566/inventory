<#
  Creates a self-signed HTTPS certificate for the portal and exports it as a PFX.
  For production prefer a certificate from your internal CA / public CA - export it as PFX and use the same env vars.

  Usage (elevated not required):
    powershell -ExecutionPolicy Bypass -File scripts\new-cert.ps1 -Names portal.company.local,192.168.1.10
  Then start the portal with:
    $env:TLS_PFX = "<path>\portal.pfx"; $env:TLS_PFX_PASSPHRASE = "<passphrase>"; $env:PORT = 8443; npm start
#>
param(
  [Parameter(Mandatory = $true)][string[]]$Names,
  [string]$Out = (Join-Path $PSScriptRoot '..\data\portal.pfx'),
  [int]$Years = 3
)
$ErrorActionPreference = 'Stop'
$dns = $Names | Where-Object { $_ -notmatch '^\d+\.\d+\.\d+\.\d+$' }
$ips = $Names | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
$san = @()
if ($dns) { $san += ($dns | ForEach-Object { "DNS=$_" }) }
if ($ips) { $san += ($ips | ForEach-Object { "IPAddress=$_" }) }
$cert = New-SelfSignedCertificate -Subject "CN=$($Names[0])" -CertStoreLocation Cert:\CurrentUser\My `
  -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($Years) `
  -KeyExportPolicy Exportable -TextExtension @("2.5.29.17={text}$($san -join '&')", '2.5.29.37={text}1.3.6.1.5.5.7.3.1')
$bytes = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pass = [Convert]::ToBase64String($bytes)
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
Export-PfxCertificate -Cert $cert -FilePath $Out -Password (ConvertTo-SecureString $pass -AsPlainText -Force) | Out-Null
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"
Write-Host "Certificate written to $((Resolve-Path $Out).Path)"
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "Passphrase: $pass"
Write-Host ''
Write-Host 'Start the portal with:'
Write-Host "  `$env:TLS_PFX='$((Resolve-Path $Out).Path)'; `$env:TLS_PFX_PASSPHRASE='$pass'; `$env:PORT='8443'; npm start"
Write-Host 'Agent traffic is end-to-end encrypted either way; with a self-signed certificate tick "Accept self-signed certificate" in the agent setup (or pass --insecure).'
