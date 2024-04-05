<#
 .Synopsis
  Diagnostic module for testing SMTP connector attribution.

 .Description
  Diagnostic module for testing SMTP connector attribution.

 .Parameter From
  The From SMTP email address.

 .Parameter To
  The To SMTP email address.

 .Parameter SmtpServer
  The remote SMTP server that will be accepting mail.

 .Parameter CertificateThumbprint
  The client certificate thumbprint to use for authentication.

 .Parameter TlsVersion
  Specify the Tls version. If none specified the default OS version is used. Accepted values are tls, tls11, tls12, tls13.

 .Parameter LogPath
  The path to the log file.

 .Example
   # Submit mail with client certificate
   Test-SmtpClientCertificate -From <FromAddress> -To <RecipientAddress> -SmtpServer your-domain.mail.protection.outlook.com -CertificateThumbprint <thumbprint>
#>

using module .\InternalSmtpClient.psm1
using module .\Utils.psm1
using module .\Logger.psm1

function Test-SmtpClientCertificate() {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    throw "The specified string is not in the form required for an e-mail address."
                }
            })]
        [string] $From,
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    throw "The specified string is not in the form required for an e-mail address."
                }
            })]
        [string] $To,
        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,
        [Parameter(Mandatory = $true)]
        [string] $CertificateThumbprint,
        [Parameter(Mandatory = $false)]
        [ValidateSet("tls", "tls11", "tls12", "tls13", IgnoreCase = $true)]
        [string] $TlsVersion,
        [Parameter(Mandatory = $false)]
        [ValidateScript({
                if (Test-Path $_ -PathType Container) {
                    $true
                }
                else {
                    throw "The location '$_' does not exist. Check the path exist and try again."
                }
            })]
        [string] $LogPath
    )

    # Check version
    CheckVersionAndWarn

    # Set Tls version
    [System.Security.Authentication.SslProtocols]$enabledSslProtocols = Get-TlsVersion -TlsVersion $TlsVersion

    # Check if running as administrator
    # Elevation is needed to gain access to the certificate private key

    if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
        Write-Warning "Missing elevation! Elevation may be required to gain access to the certificate's private key."
    }

    [Logger]$logger = New-Object Logger -ArgumentList $VerbosePreference
    [InternalSmtpClient]$smtpClient = New-Object InternalSmtpClient -ArgumentList $logger
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$clientCertificate = $null

    try {
        $clientCertificate = RetrieveCertificateFromCertStore($CertificateThumbprint)
        $smtpClient.Connect($SmtpServer, 25, $true, $false, $clientCertificate, $enabledSslProtocols)
        $smtpClient.SendMail($From, $To)
    }
    catch {
        Write-Error -ErrorRecord $_
        $logger.LogError($_.Exception, $true)
    }
    finally {
        $smtpClient.DisposeResources()
        Write-Debug "Resources disposed."
        $logger.LogMessage("[Disconnected]", "Information", "Red", $false, $true)

        # Write log to file
        $logger.WriteFile($LogPath)
    }
}
