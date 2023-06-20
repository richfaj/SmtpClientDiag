<#
MIT License

Copyright (c) 2023 Richard Fajardo

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
function CheckVersionAndWarn(){
    [version]$installedVersion = (Get-Module -Name SmtpClientDiag).Version
    [version]$latestVersion;

    try{
        # Not using proxy
        $result = Invoke-WebRequest -Uri https://github.com/richfaj/SmtpClientDiag/releases/latest/download/version.txt -TimeoutSec 10 -UseBasicParsing
        $content = [System.Text.Encoding]::UTF8.GetString($result.Content)
        $latestVersion = [version]$content
    }
    catch{
        Write-Warning "Unable to check for updates. Please check your internet connection and try again."
    }

    if($null -ne $latestVersion -and $installedVersion -lt $latestVersion){
        Write-Warning "A newer version of SmtpClientDiag is available. Please update to the latest version using Update-Module cmdlet and restart the shell."
    }
}
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
        [Parameter(Mandatory = $true, ParameterSetName = "UserProvidedToken")]
        [string] $AccessToken = $null,
        [Parameter(Mandatory = $true, ParameterSetName = "UserProvidedToken")]
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
        [Parameter(Mandatory = $false)]
        [switch] $Force
    )

    # Check version
    CheckVersionAndWarn

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
    $Script:LogVar += "# DNS Results"
    $dns = (Resolve-DnsName -Name $smtpServer -QuickTimeout)
    $dns | ForEach-Object { if ($null -ne $_.IP4Address) { Write-Verbose $_.IP4Address; $Script:LogVar += $_.IP4Address } }
    $dns | ForEach-Object { if ($null -ne $_.IP6Address) { Write-Verbose $_.IP6Address; $Script:LogVar += $_.IP6Address } }
    $Script:LogVar += ""
    }

    if ($Port -eq 0) {
        # Set default port to 587
        $Port = 587
    }

    try {
        [bool]$authSuccess = $false

        # Use OAUTH if the client id or access token was supplied
        if ((-not [System.String]::IsNullOrEmpty($ClientId)) -or (-not [System.String]::IsNullOrEmpty($AccessToken))) {
            Write-Host -ForegroundColor Yellow "[Requesting token]"
            # Check if dependency module exist
            Import-Module MSAL.PS -ErrorAction SilentlyContinue
            $module = Get-Module MSAL.PS
            if ([System.String]::IsNullOrEmpty($module)) {
                WriteError -Message "MSAL.PS module is required for obtaining an access token. Install the missing dependency using Install-Module MSAL.PS."
                return
            }

            # Obtain an access token
            $token = Get-SmtpAccessToken

            Connect
            $authSuccess = XOAUTH2Login($token)
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
    
    # Check version
    CheckVersionAndWarn

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
function Test-SmtpSaslAuthBlob() {
    param(
        [CmdletBinding()]
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$EncodedAuthBlob
    )

    $Script:BlobResult = [PSCustomObject] @{
        AuthBlobUserName   = $null
        AuthBlobToken      = $null
        OAuthTokenAudience = $null
        OAuthTokenScopes   = $null
        OAuthTokenRoles    = $null
        OAuthTokenUpn      = $null
        IsAuthBlobValid    = $false
        IsAuthTokenValid   = $false
    }

    # Write error if no auth blob is provided instead of making parameter mandatory.
    # Making it mandatory would truncate the string if user provided after execution
    if ([string]::IsNullOrEmpty($EncodedAuthBlob)) {
        Write-Error "AuthBlob is null or empty. Please supply a value to test." -ErrorAction Stop
    }

    $decodedAuthBlob = $null

    try {
        $decodedAuthBlob = DecodeBase64Value($EncodedAuthBlob)
    }
    catch {
        Write-Verbose "Failed to decode auth blob: $EncodedAuthBlob"
        Write-Error "AuthBlob is not valid base64 encoded string. Check your input and try again." -ErrorAction Stop
    }

    [char[]]$charArray = $decodedAuthBlob.ToCharArray()
    [int]$userIndex = $decodedAuthBlob.IndexOf("user=")
    [int]$authIndex = $decodedAuthBlob.IndexOf("auth=")
    [int]$bearerIndex = $decodedAuthBlob.IndexOf("Bearer ")
    [char]$ctrlA = [char]0x01

    # Validate that auth blob is correctly formatted
    # Example: base64("user=" + userName + "^Aauth=Bearer " + accessToken + "^A^A")
    # ^A represents a Control + A (%x01) character

    # Check if 'user' is present at the beginning of the string
    if ($userIndex -ne 0) {
        Write-Verbose "Invalid Authblob. Expected 'user' at index 0. IndexOf('user='):$userIndex"
        Write-Error "Authblob is incorrectly formatted. User not found." -ErrorAction Stop
    }

    if ($authIndex -eq -1) {
        Write-Verbose "Invalid Authblob. 'auth' not found in auth blob."
        Write-Error "Authblob is incorrectly formatted. Auth not found." -ErrorAction Stop
    }

    if ($bearerIndex -eq -1 -or $bearerIndex -lt $authIndex) {
        Write-Verbose "Invalid Authblob. 'Bearer' not found in auth blob or not in correct position. IndexOf('Bearer '):$bearerIndex"
        Write-Error "Authblob is incorrectly formatted. Bearer not found." -ErrorAction Stop
    }

    # Check if CTRL-A character is present before auth
    if ($charArray[$authIndex - 1] -ne $ctrlA) {
        $Script:BlobResult | Format-List
        $charHex = GetCharHexValue($charArray[$authIndex - 2])
        Write-Verbose "Invalid Authblob. Expected ascii character 0x01 before 'auth' but found char '0x$charHex' at index '$authIndex'."
        Write-Error "Authblob is incorreclty formatted. Missing CTRL-A character." -ErrorAction Stop
    }

    # Check if CTRL-A is present at the end of the string
    if ($charArray[-1] -ne $ctrlA -and $charArray[-2] -ne $ctrlA) {
        $Script:BlobResult | Format-List
        Write-Verbose "Invalid Authblob. Expected ascii character 0x01 0x01 at end of string but found '$($charArray[-1])$($charArray[-2])'."
        Write-Error "Authblob is incorreclty formatted. Missing CTRL-A character." -ErrorAction Stop
    }

    $Script:BlobResult.AuthBlobUserName = $decodedAuthBlob.Substring($userIndex + 5, $authIndex - 6)
    $Script:BlobResult.AuthBlobToken = $decodedAuthBlob.Substring($authIndex + 5, $decodedAuthBlob.Length - $authIndex - 7).Replace("Bearer ", "")

    if ([string]::IsNullOrEmpty($Script:BlobResult.AuthBlobUserName)) {
        $Script:BlobResult | Format-List
        Write-Verbose "Found 'user' in auth blob but it contains no value."
        Write-Error "AuthBlob does not contain a user" -ErrorAction Stop
    }

    if ([string]::IsNullOrEmpty($Script:BlobResult.AuthBlobToken)) {
        $Script:BlobResult | Format-List
        Write-Verbose "Found 'auth' in auth blob but it contains no value."
        Write-Error "AuthBlob does not contain a token" -ErrorAction Stop
    }

    try {
        CheckAccessToken($Script:BlobResult.AuthBlobToken)
    }
    catch {
        $Script:BlobResult | Format-List
        Write-Error $_.Exception
        Write-Error "Token in auth blob is invalid." -ErrorAction Stop
    }

    # If we get here, we're good
    $Script:BlobResult.IsAuthBlobValid = $true
    return $Script:BlobResult
}

function DecodeBase64Value([string] $value) {
    if ([string]::IsNullOrEmpty($value)) {
        return $null
    }
    $valueBytes = [System.Convert]::FromBase64String($value)
    return [System.Text.Encoding]::UTF8.GetString($valueBytes)
}

function GetCharHexValue([char] $char) {
    return ('{0:x}' -f [int]$char).ToUpper()
}

function CheckAccessToken($encodedToken) {
    if ([string]::IsNullOrEmpty($encodedToken)) {
        Write-Verbose "Token is null or empty. Skipping token verfication."
        $Script:BlobResult.IsAuthTokenValid = $false
        return
    }

    [bool]$tokenValid = $true
    [string]$decodedToken = $null
    [object]$token = $null
    [bool]$isAppAuth = $false
    [string[]]$tokenParts = $encodedToken.Split(".")

    # Token should have header, payload and signature
    if ($tokenParts.Count -ne 3 -or [string]::IsNullOrEmpty($tokenParts[0]) -or [string]::IsNullOrEmpty($tokenParts[1])) {
        throw "Invalid token. Token header or payload is null or empty."
    }

    # Can header and payload be decoded? Throws exception if not
    try {
        DecodeBase64Value($tokenParts[0]) | Out-Null
        $decodedToken = DecodeBase64Value($tokenParts[1])
        $token = ConvertFrom-Json $decodedToken
    }
    catch {
        throw "Failed to decode authentication token or token is not valid JSON."
    }

    $Script:BlobResult.OAuthTokenAudience = $token.aud
    $Script:BlobResult.OAuthTokenUpn = $token.upn
    $Script:BlobResult.OAuthTokenScopes = $token.scp
    $Script:BlobResult.OAuthTokenRoles = $token.roles

    if (-not [string]::IsNullOrEmpty($token)) {
        # Check for correct audience claim
        if ($token.aud -ne "https://outlook.office365.com" -and $token.aud -ne "https://outlook.office.com") {
            $tokenValid = $false
            Write-Verbose "Unexpected audience claim. Expected 'https://outlook.office365.com' or 'https://outlook.office.com' but found '$($token.aud)'."
            Write-Warning "Authentication token contains an invalid audience claim for SMTP Client Submission."
        }

        # Likely client credential flow if UPN claim is null or empty
        if ([string]::IsNullOrEmpty($token.upn)) {
            $isAppAuth = $true
            Write-Verbose "UPN claim is null or empty."
            Write-Warning "Application authentication detected. UPN claim not found in token."
        }

        # If using client credential flow check the roles claim
        if ($isAppAuth) {
            Write-Verbose "Checking roles claim for SMTP.SendAsApp permission."
            $permissions = $token.roles.Split()
            if (-not $permissions.Contains("SMTP.SendAsApp")) {
                $tokenValid = $false
                Write-Verbose "Not checking scopes claim as this is not user authentication."
                Write-Verbose "Invalid roles in token. Expected 'SMTP.SendAsApp' but found '$($token.roles)'."
                Write-Warning "Required permission for SMTP Client Submission not found in token."
            }
        }

        # Else check the scopes claim
        else {
            Write-Verbose "Not checking roles claim as this is not application authentication."
            Write-Verbose "Checking scopes claim for SMTP.Send permission."
            $permissions = $token.scp.Split()
            if (-not $permissions.Contains("SMTP.Send")) {
                $tokenValid = $false
                Write-Verbose "Invalid scope in token. Expected 'SMTP.Send' but found '$($token.scp)'."
                Write-Warning "Required permission for SMTP Client Submission not found in token."
            }
        }
    }
    else {
        $tokenValid = $false
    }

    $Script:BlobResult.IsAuthTokenValid = $tokenValid
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
    [int]$timeoutMs = 60000

    if($null -ne $clientCertificate)
    {
        $useClientCert = $true
    }

    if($TimeoutSec -gt 0){
        $timeoutMs = $TimeoutSec * 1000
    }

    Write-Host -ForegroundColor Yellow ("[Connecting to $SmtpServer" + ":$Port]")
    $Script:LogVar += "# Timeout Settings"
    $Script:LogVar += "TcpClientReceiveTimeOut: $($timeoutMs)s"
    $Script:LogVar += "TcpClientSendTimeOut: $($timeoutMs)s"
    $Script:LogVar += ""
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
        # TODO: Consider using DecodeBase64Value() function
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
function Get-SmtpAccessToken() {
    # Use supplied token instead if provided
    if (-not [System.String]::IsNullOrEmpty($AccessToken)) {
        Write-Verbose "User supplied AccessToken. Not fetching new token."
        return $AccessToken
    }
    else {
        Write-Verbose "Obtaining an access token using MSAL.PS module"

        $token = $null

        # Non-interactive login if client secret is provided
        if (-not [System.String]::IsNullOrEmpty($ClientSecret)) {
            Write-Verbose "Using client secret to obtain access token."
            $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -Scope 'https://outlook.office365.com/.default'
        }
        else {
            Write-Verbose "Using interactive login to obtain access token."
            $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Interactive -Scope 'https://outlook.office365.com/Smtp.Send' -LoginHint $UserName
        }
        if ([System.String]::IsNullOrEmpty($token.AccessToken)) {
            WriteError -Message "No token was available in the token request result." -StopError $true
        }

        return $token.AccessToken
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