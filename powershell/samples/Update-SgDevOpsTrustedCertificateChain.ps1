<#
.SYNOPSIS
Captures the current TLS certificate chain from a Safeguard appliance and
uploads any missing certificates to the Secrets Broker trusted store.

.DESCRIPTION
This script solves the certificate rotation problem for Safeguard On Demand
(or any Safeguard appliance using CA-signed certificates that rotate). When
the appliance's TLS certificate is renewed, the Secrets Broker's custom TLS
validation fails because the new chain certificates are not in its local trust
store.

This script:
1. Opens a raw TLS connection to the Safeguard appliance (bypassing validation)
2. Captures the full certificate chain presented during the TLS handshake
3. Connects to the Secrets Broker using an SPP token (local JWT validation -
   works even when the Secrets Broker cannot connect outbound to Safeguard)
4. Uploads each new intermediate/root certificate to the trusted store

This script can be scheduled via Task Scheduler (Windows) or cron (Linux) to
run periodically (e.g., daily) to ensure trust is maintained through
certificate rotations.

Prerequisites:
- safeguard-devops PowerShell module installed (Install-Module safeguard-devops)
- safeguard-ps PowerShell module installed (Install-Module safeguard-ps)
- Network access to both the Safeguard appliance and the Secrets Broker

.PARAMETER SgDevOpsAddress
Network address (IP or DNS) of the Secrets Broker service. May include port
delimited with a colon (e.g. ssbdevops.example.com:4443).

.PARAMETER SppAddress
Network address (IP or DNS) of the Safeguard for Privileged Passwords appliance.

.PARAMETER SppPort
Port for the Safeguard appliance TLS connection (default: 443).

.PARAMETER SppIdentityProvider
Identity provider for SPP authentication (default: "Local").

.PARAMETER SppUserName
SPP user name for authentication.

.PARAMETER SppPassword
SecureString password for SPP authentication. If omitted, you will be prompted.

.PARAMETER Insecure
If specified, bypasses TLS validation when connecting to the Secrets Broker
itself (useful when the Secrets Broker uses a self-signed web certificate).

.PARAMETER IncludeLeaf
If specified, also uploads the leaf (server) certificate. By default only
intermediate and root certificates are uploaded.

.EXAMPLE
.\Update-SgDevOpsTrustedCertificateChain.ps1 -SgDevOpsAddress ssb.example.com -SppAddress sg.example.com -SppUserName admin

.EXAMPLE
.\Update-SgDevOpsTrustedCertificateChain.ps1 -SgDevOpsAddress ssb.example.com:4443 -SppAddress sg.example.com -SppUserName svc_ssb -SppPassword $securePass -Insecure
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$SgDevOpsAddress,
    [Parameter(Mandatory=$true)]
    [string]$SppAddress,
    [Parameter(Mandatory=$false)]
    [int]$SppPort = 443,
    [Parameter(Mandatory=$false)]
    [string]$SppIdentityProvider = "Local",
    [Parameter(Mandatory=$true)]
    [string]$SppUserName,
    [Parameter(Mandatory=$false)]
    [SecureString]$SppPassword,
    [Parameter(Mandatory=$false)]
    [switch]$Insecure,
    [Parameter(Mandatory=$false)]
    [switch]$IncludeLeaf
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

Import-Module safeguard-ps
Import-Module safeguard-devops

# --- Step 1: Capture the TLS certificate chain from the Safeguard appliance ---
Write-Host "Connecting to Safeguard at ${SppAddress}:${SppPort} to capture certificate chain..."

$chainCerts = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
$tcpClient = [System.Net.Sockets.TcpClient]::new()
try
{
    $tcpClient.Connect($SppAddress, $SppPort)
    $tcpStream = $tcpClient.GetStream()

    $sslStream = [System.Net.Security.SslStream]::new(
        $tcpStream,
        $true,
        [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $certificate, $chain, $errors)
            if ($chain) {
                foreach ($element in $chain.ChainElements) {
                    $chainCerts.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($element.Certificate))
                }
            }
            elseif ($certificate) {
                $chainCerts.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate))
            }
            return $true
        }
    )

    $sslStream.AuthenticateAsClient($SppAddress)
    $sslStream.Dispose()
}
finally
{
    $tcpClient.Dispose()
}

if ($chainCerts.Count -eq 0) {
    throw "Failed to capture any certificates from ${SppAddress}:${SppPort}"
}

Write-Host "Captured $($chainCerts.Count) certificate(s) in the chain:" -ForegroundColor Green
for ($i = 0; $i -lt $chainCerts.Count; $i++) {
    $cert = $chainCerts[$i]
    $role = if ($i -eq 0) { "Leaf" } elseif ($cert.Subject -eq $cert.Issuer) { "Root" } else { "Intermediate" }
    Write-Host "  [$i] $role - Subject: $($cert.Subject) | Thumbprint: $($cert.Thumbprint) | Expires: $($cert.NotAfter)"
}

# --- Step 2: Connect to Secrets Broker ---
Write-Host "Authenticating to Safeguard at ${SppAddress}..."

$connectParams = @{
    Insecure = $true
}
if ($SppPassword) {
    $connectParams["Password"] = $SppPassword
}

Connect-Safeguard $SppAddress $SppIdentityProvider $SppUserName @connectParams

try {
    Write-Host "Connecting to Secrets Broker at ${SgDevOpsAddress}..."
    if ($Insecure) {
        Connect-SgDevOps $SgDevOpsAddress -Insecure
    } else {
        Connect-SgDevOps $SgDevOpsAddress
    }

    try {
        # --- Step 3: Upload chain certificates ---
        $existingCerts = Get-SgDevOpsTrustedCertificate
        $existingThumbprints = @()
        if ($existingCerts) {
            $existingThumbprints = @($existingCerts | ForEach-Object { $_.Thumbprint })
        }

        $startIndex = if ($IncludeLeaf) { 0 } else { 1 }
        $uploaded = 0
        $skipped = 0

        for ($i = $startIndex; $i -lt $chainCerts.Count; $i++) {
            $cert = $chainCerts[$i]

            if ($existingThumbprints -contains $cert.Thumbprint) {
                Write-Host "  Skipping (already trusted): $($cert.Subject)" -ForegroundColor Yellow
                $skipped++
                continue
            }

            $b64 = [System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            $lines = [System.Collections.Generic.List[string]]::new()
            $lines.Add("-----BEGIN CERTIFICATE-----")
            for ($j = 0; $j -lt $b64.Length; $j += 64) {
                $lines.Add($b64.Substring($j, [System.Math]::Min(64, $b64.Length - $j)))
            }
            $lines.Add("-----END CERTIFICATE-----")
            $pemCert = $lines -join "`n"

            Write-Host "  Uploading: $($cert.Subject) ($($cert.Thumbprint))" -ForegroundColor Green
            Invoke-SgDevOpsMethod POST "Safeguard/TrustedCertificates" -Parameters @{ importFromSafeguard = $false } -Body @{
                Base64CertificateData = $pemCert
            } | Out-Null
            $uploaded++
        }

        Write-Host ""
        Write-Host "Done. Uploaded: $uploaded, Skipped (already trusted): $skipped" -ForegroundColor Cyan

        Disconnect-SgDevOps
    }
    catch {
        try { Disconnect-SgDevOps } catch {}
        throw
    }
}
finally {
    Disconnect-Safeguard
}
