<#
 .Synopsis
  Diagnostic module for testing SMTP client submission.

 .Description
  Diagnostic module for testing SMTP client submission. This function supports Basic (AUTH LOGIN) and Modern (XOAUTH2) authentication.

 .Parameter From
  The From SMTP email address.

 .Parameter To
  The To SMTP email address.

 .Parameter UseSsl
  Enables the use of TLS if supported by the remote MTA.

 .Parameter AcceptUntrustedCertificates
  Disables certificate validation

 .Parameter TlsVersion
  Specify the Tls version. If none specified the default OS version is used. Accepted values are tls, tls11, tls12, tls13.

 .Parameter SmtpServer
  The remote SMTP server that will be accepting mail.

 .Parameter Port
  The remote network port number. By default the port is 587 if not specified.

 .Parameter Credential
  User credentials for basic authentication.

 .Parameter AccessToken
  Optional parameter to consume an external token.

 .Parameter UserName
  Username of the account for modern authentication. Required to build the auth blob.

 .Parameter ClientId
  Azure Application Client Id.

 .Parameter TenantId
  Azure / Office 365 Tenant Id.

 .Parameter TimeoutSec
  Optional parameter to force a timeout value other than the default of 10 seconds.

 .Parameter Force
  Optional parameter to force mail submission.

 .Example
   # Submit mail without credentials.
   Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.office365.com -Port 25 -Force

 .Example
   # Submit mail using legacy authentication.
   Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.office365.com -Port 587 -Credential <PSCredential>

 .Example
   # Submit mail using modern authentication.
   Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.office365.com -Port 587 -UserName <MailboxSmtp> -ClientId 9954180a-16f4-4683-aaaaaaaaaaaa -TenantId 1da8c747-60dd-4404-8418-aaaaaaaaaaaa
#>
using module .\InternalSmtpClient.psm1
using module .\Utils.psm1
using module .\Logger.psm1

function Test-SmtpClientSubmission() {
    [CmdletBinding(DefaultParameterSetName = "Default")]
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
        [Parameter(Mandatory = $false)]
        [switch] $UseSsl,
        [Parameter(Mandatory = $false)]
        [switch] $AcceptUntrustedCertificates,
        [Parameter(Mandatory = $false)]
        [ValidateSet("tls", "tls11", "tls12", "tls13", IgnoreCase = $true)]
        [string] $TlsVersion,
        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,
        [Parameter(Mandatory = $false)]
        [int] $Port = 587,
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [Parameter(Mandatory = $false, ParameterSetName = "Force")]
        [pscredential] $Credential,
        [Parameter(Mandatory = $true, ParameterSetName = "UserProvidedToken")]
        [string] $AccessToken,
        [Parameter(Mandatory = $true, ParameterSetName = "UserProvidedToken")]
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    throw "The specified string is not in the form required for an e-mail address."
                }
            })]
        [string] $UserName,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [ValidateScript({
                [System.Guid]::Parse($_) | Out-Null
                $true
            })]
        [guid] $ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [ValidateScript({
                [System.Guid]::Parse($_) | Out-Null
                $true
            })]
        [guid] $TenantId,
        [Parameter(Mandatory = $false, ParameterSetName = "OAuth_app")]
        [SecureString] $ClientSecret,
        [Parameter(Mandatory = $false)]
        [ValidateScript({
                if (Test-Path $_ -PathType Container) {
                    $true
                }
                else {
                    throw "The location '$_' does not exist. Check the path exist and try again."
                }
            })]
        [string] $LogPath,
        [Parameter(Mandatory = $false)]
        [int] $TimeoutSec,
        [Parameter(Mandatory = $true, ParameterSetName = "Force")]
        [switch] $Force
    )

    # Check version
    CheckVersionAndWarn
    [Logger]$logger = New-Object Logger -ArgumentList $VerbosePreference
    [InternalSmtpClient]$smtpClient = New-Object InternalSmtpClient -ArgumentList $logger
    if ($TimeoutSec -gt 0) {
        $smtpClient.TimeoutSec = $TimeoutSec
    }

    # Set Tls version
    $enabledSslProtocols = Get-TlsVersion -TlsVersion $TlsVersion

    # Check if hostname is IP address
    $ipv4Regex = '^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$'
    if ($SmtpServer -match $ipv4Regex) {
        $logger.LogMessage("Certificate validation will fail when using an IP address. Consider using a hostname or use -AcceptUntrustedCertificate switch if testing.", "Warning", $null, $true, $true)
    }
    else {
        # Verbose details for name resolution
        $logger.LogMessage("Resolving hostname to IP addresses...", "Information", $true, $true)
        $logger.LogMessage("# DNS Results", "Information", $true, $true)

        # Use .Net DNS resolver to avoid DnsClient module loading overhead
        $ipAddresses = Invoke-DotNetDnsResolver -HostName $smtpServer
        if ($ipAddresses.Count -eq 0) {
            $logger.LogMessage("No IP addresses resolved for hostname.", "Warning", $null, $true, $true)
        }
        else {
            foreach ($ip in $ipAddresses) {
                $logger.LogMessage("$($ip.ToString())", "Information", $true, $true)
            }
        }
        $logger.LogMessage("", "Information", $true, $true)
    }

    try {
        [bool]$authSuccess = $false

        # Use OAUTH if the client id or access token was supplied
        if (($null -ne $ClientId) -or (-not [System.String]::IsNullOrEmpty($AccessToken))) {
            $logger.LogMessage("[Requesting token]", "Information", "Yellow", $false, $true)

            # Obtain an access token
            Import-Module MSAL.PS -ErrorAction Stop
            $token = Get-SmtpAccessToken -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -AccessToken $AccessToken -UserName $UserName -VerbosePref $VerbosePreference

            $smtpClient.Connect($SmtpServer, $Port, $UseSsl, $AcceptUntrustedCertificates, $null, $enabledSslProtocols)
            $authSuccess = $smtpClient.XOAUTH2Login($UserName, $token)
        }
        # Else if no client id check if credentials are available and use legacy auth
        else {
            $smtpClient.Connect($SmtpServer, $Port, $UseSsl, $AcceptUntrustedCertificates, $null, $enabledSslProtocols)
            if ($null -ne $Credential) {
                # Legacy auth
                $authSuccess = $smtpClient.AuthLogin($Credential)
            }
        }
        # Send mail
        if ($authSuccess -eq $true) {
            $logger.LogMessage("Authentication successful", "Verbose", $false, $true)
            $smtpClient.SendMail($From, $To)
        }

        # If force switch true, send mail anyway if auth failed or no creds available
        if ($authSuccess -eq $false -and $Force -eq $true) {
            $logger.LogMessage("Forcing mail submission", "Verbose", $false, $true)
            $smtpClient.SendMail($From, $To)
        }
        elseif ($authSuccess -eq $false) {
            $smtpClient.SmtpCmd("QUIT")
        }
        $logger.LogMessage("Done.", "Verbose", $false, $true)
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

