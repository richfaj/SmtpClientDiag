<#
MIT License

Copyright (c) 2022 Richard Fajardo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

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
function Test-SmtpClientSubmission() {
    param(
        [CmdletBinding(DefaultParameterSetName = 'LegacyAuth')]
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    # Throw away exception
                }
        
                throw "The specified string is not in the form required for an e-mail address."
            })]
        [string] $From,
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    # Throw away exception
                }
        
                throw "The specified string is not in the form required for an e-mail address."
            })]
        [string] $To,
        [Parameter(Mandatory = $false)]
        [switch] $UseSsl,
        [Parameter(Mandatory = $false)]
        [switch] $AcceptUntrustedCertificates,
        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,
        [Parameter(Mandatory = $false)]
        [int] $Port,
        [Parameter(Mandatory = $true, ParameterSetName = "LegacyAuth")]
        [pscredential] $Credential = $null,
        [Parameter(Mandatory = $false, ParameterSetName = "Token")]
        [string] $AccessToken = $null,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    # Throw away exception
                }
        
                throw "The specified string is not in the form required for an e-mail address."
            })]
        [string] $UserName,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [ValidateScript({
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [guid] $ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [ValidateScript({
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [guid] $TenantId,
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
        [Parameter(Mandatory = $false)]
        [switch] $Force
    )

    [System.IO.StreamReader]$Script:reader
    [System.IO.StreamWriter]$Script:writer
    [int]$Script:responseCode = 0
    [string]$Script:smtpResponse
    [string[]]$Script:sessionCapabilities
    [System.Collections.Generic.List[PSObject]]$Script:LogVar = @()

    # Check if hostname is IP address
    $ipv4Regex = '^(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|[0-1]?\d{1,2})){3}$'
    if($SmtpServer -match $ipv4Regex){
        Write-Warning "Certificate validation will fail when using an IP address. Consider using a hostname or use -AcceptUntrustedCertificate swtich if testing."
    }
    else{
    # Verbose details for name resolution
    Write-Verbose "Resolving hostname to IP addresses..."
    $dns = (Resolve-DnsName -Name $smtpServer -QuickTimeout)
    $dns | ForEach-Object { if ($null -ne $_.IP4Address) { Write-Verbose $_.IP4Address } }
    $dns | ForEach-Object { if ($null -ne $_.IP6Address) { Write-Verbose $_.IP6Address } }
    }

    if ($Port -eq 0) {
        # Set default port to 587
        $Port = 587
    }

    try {
        [bool]$authSuccess = $false

        # Use OAUTH if the client id was supplied
        if (-not [System.String]::IsNullOrEmpty($ClientId)) {
            Write-Host -ForegroundColor Yellow "[Requesting token]"
            # Check if dependency module exist
            Import-Module MSAL.PS -ErrorAction SilentlyContinue
            $module = Get-Module MSAL.PS
            if ([System.String]::IsNullOrEmpty($module)) {
                WriteError -Message "MSAL.PS module is required for obtaining an access token. Install the missing dependency using Install-Module MSAL.PS."
                return
            }

            # Obtain an access token first
            $token = GetAccessToken
            if ([System.String]::IsNullOrEmpty($token)) {
                return
            }

            Connect
            $authSuccess = XOAUTH2Login($token.AccessToken)
        }
        # Else if no client id check if credentials are available and use legacy auth
        else {
            Connect
            if (-not [System.String]::IsNullOrEmpty($Credential)) {
                # Legacy auth
                $authSuccess = AuthLogin
            }
        }
        # Send mail
        if ($authSuccess -eq $true) {
            Write-Verbose "AUTH LOGIN success"
            SendMail
        }

        # If force switch true, send mail anyway if auth failed or no creds available
        if ($authSuccess -eq $false -and $Force -eq $true) {
            Write-Verbose "Forcing mail submission"
            SendMail
        }
        Write-Verbose "Done."
    }
    catch {
        # Display last exception
        WriteMessage($_)
        Write-Error -ErrorRecord $_
    }
    finally {
        <#Do this after the try block regardless of whether an exception occurred or not#>
        if ($null -ne $Script:reader) { $Script:reader.Dispose() }
        if ($null -ne $Script:writer) { $Script:writer.Dispose() }
        if ($null -ne $Script:tcpClient) { $Script:tcpClient.Dispose() }

        # Reset/clear variables
        $Script:reader = $null
        $Script:writer = $null
        $Script:responseCode = 0
        $Script:smtpResponse = $null
        $Script:sessionCapabilities = $null

        Write-Debug "Resources disposed."
        Write-Host -ForegroundColor Red "[Disconnected]"

        # Write log to file
        WriteFile
    }
}

function Test-ConnectorAttribution()
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    # Throw away exception
                }
        
                throw "The specified string is not in the form required for an e-mail address."
            })]
        [string] $From,
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                try {
                    $null = [mailaddress]$_
                    return $true
                }
                catch {
                    # Throw away exception
                }
        
                throw "The specified string is not in the form required for an e-mail address."
            })]
        [string] $To,
        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,
        [Parameter(Mandatory = $true)]
        [string] $CertificateThumbprint,
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
        [Parameter(DontShow = $true, Mandatory = $false)]
        [int]$Port,
        [Parameter(DontShow = $true, Mandatory = $false)]
        [bool]$UseSsl
    )

    # Check if running as administrator
    # Admin is needed to gain access to the certificate private key
    # Future version may add support for PFX file instead

    if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false)
    {
        Write-Warning "PowerShell session is not running as admin. Not running as admin may prevent the module from gaining access to the certificate private key."
    }

    [System.IO.StreamReader]$Script:reader
    [System.IO.StreamWriter]$Script:writer
    [int]$Script:responseCode = 0
    [string]$Script:smtpResponse
    [string[]]$Script:sessionCapabilities
    [System.Collections.Generic.List[PSObject]]$Script:LogVar = @()
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$clientCertificate = RetrieveCertificateFromCertStore($CertificateThumbprint)
    $Port = 25
    $UseSsl = $true

    try{
        Connect($clientCertificate)
        SendMail
    }
    catch {
        # Display last exception
        WriteMessage($_)
        Write-Error -ErrorRecord $_
    }
    finally {
        <#Do this after the try block regardless of whether an exception occurred or not#>
        if ($null -ne $Script:reader) { $Script:reader.Dispose() }
        if ($null -ne $Script:writer) { $Script:writer.Dispose() }
        if ($null -ne $Script:tcpClient) { $Script:tcpClient.Dispose() }

        # Reset/clear variables
        $Script:reader = $null
        $Script:writer = $null
        $Script:responseCode = 0
        $Script:smtpResponse = $null
        $Script:sessionCapabilities = $null

        Write-Debug "Resources disposed."
        Write-Host -ForegroundColor Red "[Disconnected]"

        # Write log to file
        WriteFile
    }
}

function RetrieveCertificateFromCertStore($thumbprint) {
    $cert = Get-ChildItem -Path "cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq $thumbprint}

    if ($null -eq $cert -or ($cert | Measure-Object).Count -eq 0) {
        Write-Error "No certificates found with thumbprint '$thumbprint' in LocalMachine certificate store." -ErrorAction Stop
    }

    # There should only be one certificate
    if (($cert | Measure-Object).Count -gt 1) {
        Write-Error "More than one certificate found with thumbprint '$thumbprint'." -ErrorAction Stop
    }

    Write-Verbose "Found certificate with thumbprint '$thumbprint' in LocalMachine certificate store."
    return $cert
}
function Connect($clientCertificate) {
    [bool]$useClientCert = $false
    [int]$timeoutMs = 10000

    if($null -ne $clientCertificate)
    {
        $useClientCert = $true
    }

    if($TimeoutSec -gt 0){
        $timeoutMs = $TimeoutSec * 1000
    }

    Write-Host -ForegroundColor Yellow ("[Connecting to $SmtpServer" + ":$Port]")
    $Script:LogVar += "Connecting to $SmtpServer" + ":$Port"

    $Script:tcpClient = New-Object System.Net.Sockets.TcpClient
    $Script:tcpClient.ReceiveTimeout = $timeoutMs
    $Script:tcpClient.SendTimeout = $timeoutMs

    $result = $Script:tcpClient.BeginConnect($SmtpServer, $Port, $null, $null)
    $result.AsyncWaitHandle.WaitOne($timeoutMs) | Out-Null

    if (!$Script:tcpClient.Connected) {
        $remoteHostString = $SmtpServer + ":" + $Port
        WriteError -Message "Connection to remote host $remoteHostString failed! Using tcp timeout: $($TimeoutSec)s." -StopError $true
    }
    else {
        $Script:tcpClient.EndConnect($result)
    }

    Write-Host -ForegroundColor Green "[Connected]"

    $Script:reader = New-Object System.IO.StreamReader::($Script:tcpClient.GetStream())
    $Script:writer = New-Object System.IO.StreamWriter::($Script:tcpClient.GetStream())

    ReadResponse
    SendEhlo

    if ($UseSsl) {
        Write-Verbose "Starting TLS..."
        if ($Script:sessionCapabilities.Contains("STARTTLS")) {
            SmtpCmd("STARTTLS")
            if ($Script:responseCode -eq 220) {
                WriteMessage("* Starting TLS negotation")
                if ($AcceptUntrustedCertificates) {
                    Write-Verbose "Ignoring certificate validation results."
                    $sslstream = New-Object System.Net.Security.SslStream::($Script:tcpClient.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
                }
                else {
                    $sslstream = New-Object System.Net.Security.SslStream::($Script:tcpClient.GetStream())
                }

                if($useClientCert){
                    $certcol = New-object System.Security.Cryptography.X509Certificates.X509CertificateCollection
                    $certcol.Add($clientCertificate)
                    $sslstream.AuthenticateAsClient($SmtpServer, $certcol, $true)
                }
                else{
                    $sslstream.AuthenticateAsClient($SmtpServer)
                }

                $Script:writer = New-Object System.IO.StreamWriter::($sslstream)
                $Script:reader = New-Object System.IO.StreamReader::($sslstream)

                WriteMessage("* TLS negotiation completed." + " CipherAlgorithm:" + $sslstream.CipherAlgorithm + " TlsVersion:" + $sslstream.SslProtocol)
                WriteMessage("* RemoteCertificate: IgnoreCertValidation:$AcceptUntrustedCertificates " + "<S>" + $sslstream.RemoteCertificate.Subject + "<I>" + $sslstream.RemoteCertificate.Issuer)
                if($useClientCert)
                {
                    WriteMessage("* ClientCertificate: <S>" + $sslstream.LocalCertificate.Subject + "<I>" + $sslstream.LocalCertificate.Issuer)
                }

                # Warn if using unsupported versions of TLS
                if ($sslstream.SslProtocol -eq "Tls" -or $sslstream.SslProtocol -eq "Tls11"){
                    Write-Warning "TLS version is either 1.0 or 1.1. Consider enabling TLS 1.2 or greater."
                }

                $rawCert = "`n-----BEGIN CERTIFICATE-----"
                $rawCert += "`n" + [Convert]::ToBase64String($sslstream.RemoteCertificate.GetRawCertData())
                $rawCert += "`n-----END CERTIFICATE----- "

                Write-Verbose "Remote Certificate:"
                Write-Verbose $rawCert

                # Rediscover session capabilities
                SendEhlo
            }
            else {
                WriteError -Message "Failed to start tls session with remote host."
            }
        }
        # STARTTLS verb not found
        else {
            WriteError -Message "Session capabilities do not support STARTTLS."
        }
    }
}
function ReadResponse() {
    # Clear any prior responses and response codes
    $Script:responseCode = -1
    $Script:smtpResponse = $null

    # Bail if not connected
    if ($Script:tcpClient.Connected -eq $false) {
        WriteMessage("Client is not connected.")
        return
    }

    $line = $reader.ReadLine()

    if ([System.String]::IsNullOrEmpty($line)) {
        return $responseCode
    }

    $Script:smtpResponse += $line

    # Parse response code
    $Script:responseCode = [System.Int32]::Parse($line.Substring(0, 3))

    # Read all lines
    while ($Script:reader.Peek() -gt 0) {
        Write-Debug "StreamReader: Reading more lines..."
        $line = $Script:reader.ReadLine()
        if ([System.String]::IsNullOrEmpty($line)) {
            WriteError -Message "End of stream."
        }
        $Script:smtpResponse += "," + $line.Substring(4)
    }

    WriteMessage("< " + $Script:smtpResponse)
}
function SendEhlo() {
    SmtpCmd("EHLO " + ([System.Environment]::MachineName))

    if ($Script:responseCode -eq 250) {
        # Skip banner
        $lines = $Script:smtpResponse.Split(',') | Where-Object { ($_) -and ($_ -notcontains "250") }

        # Clear any previous capabilities
        $Script:sessionCapabilities = $null
        $Script:sessionCapabilities = $lines
    }
    else {
        Write-Host "SMTP Command EHLO failed. Response Code: " $Script:responseCode
    }
}
function SmtpCmd([string]$command, [bool]$redactCmd) {
    if ($redactCmd) {
        Write-Verbose "Sending command: *REDACTED*"
        WriteMessage("> *REDACTED*")
    }
    else {
        Write-Verbose "Sending command: $command"
        WriteMessage("> " + $command)
    }

    if ($null -eq $Script:writer) {
        WriteError -Message "StreamWriter is null"
        return
    }

    $Script:writer.WriteLine($command)
    $Script:writer.Flush()

    if (($command -ne "QUIT") -and (!$command.StartsWith("BDAT"))) {
        ReadResponse
    }
}
function ContainsCapability([string] $c) {
    foreach ($cap in $Script:sessionCapabilities) {
        if ($cap.ToLower().Contains($c.ToLower())) {
            return $true
        }
    }

    return $false
}
function AuthLogin() {
    if (ContainsCapability("AUTH LOGIN")) {
        SmtpCmd("AUTH LOGIN")

        if ($Script:responseCode -eq 334) {
            $message = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Script:smtpResponse.Substring(4))).ToLower()
            if ($message -eq "username:") {
                SmtpCmd ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credential.UserName)))
            }
            # Decode the response
            $message = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Script:smtpResponse.Substring(4))).ToLower()

            # If username accepted continue
            if (($Script:responseCode -eq 334) -and ($message -eq "password:")) {
                SmtpCmd ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credential.GetNetworkCredential().Password))) -redactCmd $true
            }
            else {
                WriteError -Message "SMTP Authentication Failed. Invalid user name."
                return $false
            }
            if ($Script:responseCode -eq 421){
                WriteError -Message "SMTP Authentication Failed. Check your TLS version is at least 1.2."
                return $false
            }
            if ($Script:responseCode -ne 235) {
                WriteError -Message "SMTP Authentication Failed. Check user name and password."
                return $false
            }

            return $true
        }
        else {
            WriteError -Message "Unexpected response code on AUTH LOGIN."
        }
    }
    else {
        WriteMessage -Message "Session capabilities do not support AUTH LOGIN"
    }
    return $false
}
function XOAUTH2Login([string]$token) {
    if ([System.String]::IsNullOrEmpty($token)) {
        WriteError -Message "AccessToken is null or empty"
        return
    }
    # Build the token
    $authBlob = "user=" + $UserName + "$([char]0x01)auth=Bearer " + $token + "$([char]0x01)$([char]0x01)"

    if (ContainsCapability("XOAUTH2")) {
        SmtpCmd("AUTH XOAUTH2")

        if ($Script:responseCode -eq 334) {
            SmtpCmd([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($authBlob)))

            if ($Script:responseCode -eq 235) {
                return $true
            }
            if ($Script:responseCode -eq 421){
                WriteError -Message "SMTP Authentication Failed. Check your TLS version is at least 1.2."
                return $false
            }
            else {
                return $false
            }
        }
        else {
            WriteError -Message "Unexpected response code."
            return $false
        }
    }
    else {
        WriteError -Message "Session capabilities do not support AUTH XOAUTH2."
        return $false
    }
}
function GetAccessToken() {
    # Use supplied token instead if provided
    if (-not [System.String]::IsNullOrEmpty($AccessToken)) {
        Write-Verbose "User supplied AccessToken. Not fetching new token."
        return $AccessToken
    }
    else {
        Write-Verbose "Obtaining an access token using MSAL.PS module"

        $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Interactive -Scope 'https://outlook.office365.com/Smtp.Send' -LoginHint $UserName
        if ([System.String]::IsNullOrEmpty($token.AccessToken)) {
            WriteError -Message "No token was available in the token request result". -StopError $true
        }

        return $token
    }
}
function SendMail() {
    SmtpCmd("MAIL FROM: <$From>")
    if ($Script:responseCode -ne 250) {
        WriteError -Message "Unexpected response code on MAIL FROM command."
        SmtpCmd("QUIT")
        return
    }

    SmtpCmd("RCPT TO: <$To>")
    if ($Script:responseCode -ne 250) {
        WriteError -Message "Unexpected response code on TO command."
        SmtpCmd("QUIT")
        return
    }

    $message = "From: `"$From`" <$From>"
    $message += "`nTo: `"$To`" <$To>"
    $message += "`nSubject: SMTP Client Submission Test"
    $message += "`nContent-Type: text/plain"
    $message += "`n"
    $message += "`nThis is a test message."

    # Script does not check for chuncking capability as it is not meant to support all MTAs
    # BDAT is preferred over DATA command
    $byteCount = [System.Text.Encoding]::ASCII.GetByteCount($message)
    $command = "BDAT $byteCount LAST"

    SmtpCmd($command)

    Write-Verbose "Writing message to stream..."
    $Script:writer.Write($message)
    $Script:writer.Flush()

    ReadResponse
    
    if ($Script:responseCode -ne 250) {
        WriteError -Message "Failed to submit message."
    }

    SmtpCmd("QUIT")
}
function WriteError() {
    param(
        [CmdletBinding()]
        [Parameter(Mandatory = $true)]
        $Message,
        [Parameter(Mandatory = $false)]
        $StopError
    )
    $out = (Get-Date).ToUniversalTime().ToString() + " " + $message
    $Script:LogVar += $out

    if ($StopError) {
        Write-Error -Message $Message -ErrorAction Stop
    }
    else {
        Write-Error -Message $Message
    }
}
function WriteMessage($message) {
    # Format output
    $out = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddThh:mm:ss.fffK") + " " + $message
    Write-Host $out

    # Save to variable for logging
    $Script:LogVar += $out
}
function WriteFile() {
    [string]$fileName = "smtpdiag_" + (Get-Date).ToUniversalTime().ToString("MMddyyyyss") + ".log"
    [string]$joinedPath

    # Check if custom log path provided
    if (-not [System.String]::IsNullOrEmpty($LogPath)) {
        $joinedPath = Join-Path -Path $LogPath -ChildPath $fileName
    }

    # Use working directory
    else {
        # Check path exist
        if ((Test-Path 'logs' -PathType Container) -eq $false) {
            New-Item -Path 'logs' -ItemType Directory -Force | Out-null
        }

        $joinedPath = Join-Path -Path (Get-Location).Path -ChildPath $fileName
    }

    Write-Host -ForegroundColor Green "Saved log file to: $joinedPath"

    $Script:LogVar += "---End of Session---"
    $Script:LogVar | Out-File -FilePath $joinedPath -Append -Force
}
# SIG # Begin signature block
# MIIm8QYJKoZIhvcNAQcCoIIm4jCCJt4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQPmHa6muyjZruzU0vxasw1xR
# iaKggiCZMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTla
# MEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGln
# aUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh9J0J
# dz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdC
# riak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58tySSge
# TIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0
# jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdP
# bnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2
# Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZ
# IS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMv
# wi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8J
# JVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mD
# jcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8
# jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP
# 1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCb
# Ex2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojO
# fRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkV
# NTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/
# HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkj
# gNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclT
# uf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgDQkfo
# QTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg
# 53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54
# BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYB
# DriL7ubgclWJLCcZYfZ3AYwwggbaMIIEwqADAgECAhAK8fGpgdDQ6zuhzgVq4ZM+
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMwMzExMDAwMDAwWhcNMjUw
# MzEzMjM1OTU5WjBiMQswCQYDVQQGEwJVUzEOMAwGA1UECBMFVGV4YXMxDzANBgNV
# BAcTBklydmluZzEYMBYGA1UEChMPUmljaGFyZCBGYWphcmRvMRgwFgYDVQQDEw9S
# aWNoYXJkIEZhamFyZG8wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDD
# B/LF41G1K6RKgwRDOb7Xbk9bhLq49MZqfEnjTQmb4qbHO62eHerCu4KXPX7GZMJ+
# gVXkAIqfYQQNN8ZjStLAXThcwLJNZh0r2WxWIn7+32/Wxw0FIryn8pCGmYGZg/7Q
# /r5/xYNalDr+v3zIQfh+M24vS5/MScvS6JBiYVzY8DWtTF3zVvkEymodwXvtgwHW
# 35JhI3x/ZCHwUF5oml0Yb8tEqzA5+t6xpNZzAZzvu37w4A4Zff8yPHGQTx3J/5Mp
# f3Sot0YJrhcUT7jruFd42QzNM/h1XIbgYP1k4ziiYQJvFpzfECVh/aNGf14fi4xp
# vgGaTpaHl0hwRFDf98RLLW5Zu6hC1P0L3S6o7REee0YBCrw+qKyhRCg10F6rTp03
# qTTwcZpOasQ9Kr8UwaTSXOX8ZK14zwDu2zPwPROb0zQO8iTe6kXXWqvdUEEfOnrQ
# sfkSRvYtRRZZo7yg7IV7PHNe7rw0d68vehV4fWMEBtyMCn73/9aZJeaiTV3Vmb0C
# AwEAAaOCAgMwggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0G
# A1UdDgQWBBRuiLbpWMGylpjQJUCtiXDxz1BqNDAOBgNVHQ8BAf8EBAMCB4AwEwYD
# VR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIw
# MjFDQTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQ
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkq
# hkiG9w0BAQsFAAOCAgEAa0gT+pd1VFRCjkAPufANs/IKePLLie6X3BXbUKVih0Y6
# tFetfp/tT4K9v3nxZrRMWNH3fe4/88G3SwJPZKgEuI2LkeFpNXYuNphA9ZUJIkTn
# VBSnze86tiyaSguVhwr7BOUs4KHuSqu2/Ey8lUn9lJaXLHp/as0NWWXEg5lSH7oh
# pBhEOH2pIXMcS/RIaOPH8HqWZ6QK9JEO/0kFTfTKbeFJFWkVFSq0JI0yR8VtQxk2
# isFG9sUTLZ1v24+BEnBwDfSWCI6+VKbQlMoOURWZ9X51B7autZA3cEagPxvsIJYF
# gFFpmq/aRiju63NO4hfIqiD8rKzFc/Alp55GV3ySem8OSXgIp3uRk0NEcn9j/jxf
# UciEEhKeyO7gwVl1SAYop7fTyAt8+n5ByrFQO1uMMdn2nL0wgxvipp5xmdBKiLsN
# /Z3trUVgljmyqrNy7BCzfbHaIuN/zoRf0I+tLt0vqH/hGqcMVLkLqFYRPLRxTaZL
# pBDSeit0lFkht+0Y9W8paUaoCCxxobFCkgrUworgetebOHE9Cc11Ibos+rJqGapf
# gn8vwOwSL32VOkqbnH7eGdoJuHvqPbBv96k0EkQyAetR6vdhnhDrzce/NBPUafYk
# dvxeYILGMUEN4UMTUHxhUBjQNtTnJCDdj+02ssYzZrymtXxoetVWHel6rFJcyPox
# ggXCMIIFvgIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEArx8amB0NDrO6HOBWrhkz4wCQYFKw4D
# AhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZI
# hvcNAQkEMRYEFA3jtI8kEjistNfHJM03g3wZjKbrMA0GCSqGSIb3DQEBAQUABIIB
# gLkP0xgcvtqMA4L5kinkDzsD1n7R3eiSzMkuBIQrLT88f/CHn5JDbD7yoWuttOK6
# ACuWSX8ec8zux4mRUubD3nhF0MMscN4kK/jTkByxFxNJgDQVPSbCn/z4uGR7w9iI
# JMdB9g/CWdddEuYM5Da1X3TV9Fc13473ZMI1LdG/bfqGAk5z1MCEkjURxU0gVpJX
# FGOMfqT8NGrX8WjXVRijVrgnx0ymwalG9bQFA44OzEANwWFbGTGRBkVeaDdNp3FC
# uIditSiXKK+/6C9r0ruwseAsVSQL8/8Gxj0iTBQ/cotUqF4BVr5nDRsKpWlCn4Zm
# OaaoXYGBQ3aUvH8BjD6sPUDbBO8eAM6F0gmSUm5I0kTqDjOw/tIEpDgJ+nwjSWjm
# x2TJ2NpYbiyMuSdmU3NAG6DOceAWNp23zdKr1jjWTNduAUI6gU9/191iJJ15sTwc
# VdJwFckzre5eL14Tmn9imG8/g5/EQdPmVRoj7Tlm41s6maFO4slIEbedzIK0IXU+
# 8qGCAyAwggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAxNaXJLlPo8
# Kko9KQeAPVowDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yMzAzMTIxOTA1MTNaMC8GCSqGSIb3DQEJBDEi
# BCBWGTAAiGH/w6SQBK32JBgWwT7cmOrNyXpOTaVIcW/EwzANBgkqhkiG9w0BAQEF
# AASCAgCqW0MBeTQTjBZn22/epyCYurRFFfpE9zZ5FZ0jp2dDlvcXZyiVEpKfO6Qn
# 9SCexcjevQwL+V6kbZo6b1nMv79Ls9LxrM1ZZxPrH7D5wyssTB5NqO42g5QJrUyd
# lA+9bZoomtKFXygRt5D03JQIS9vr6D6ns7zldasDhBmq6YuryA68iaeUy/FIU6vY
# Agft/f15ejPZqVnYPoo+b/+qkJ6OFovfUMHAugrF1qx3mBGDahwNO2FoQzbOrE7v
# KKCFaDAJP+t9ddXzhdQsy/x5PMKcAzA+XqIZ4uTamaCSNVrUQzZa/VQ8JEdIqbXJ
# N6l+4lrDBm/AzoS9NCp9yek0XUrVXfoISJ8xtc1LqwvKmLSOj0HOxQDF98uW3VUP
# vL23irlzNWpoaOIJHXTkoscD8t0jKiVFN0SJxMuzcWs903kMpMt79olvSK9t/d8r
# yccreE2fXFAo86KN7dNqjLmtduuoipAYVVzeILbGexgA8xQaiaJSLuTskmDTFNuS
# Fmqbs3eu/87epjAoIuSQ/Q06f/2BSP4gspuCrAffIxHDGzvFjTx33tBUC/w0rkCL
# +o4pKlV5BBXXdeb3E4xgphJ239UtptvedrYJ+4G0S/wU/w/wVkWv1MRQhofhm91r
# W0VWfCEPv/fomtZ+4eqWgVPooURF+A5xMxNV6hpBd6qlnKS5lw==
# SIG # End signature block
