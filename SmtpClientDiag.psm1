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
        [string] $From,
        [Parameter(Mandatory = $true)]
        [string] $To,
        [Parameter(Mandatory = $false)]
        [switch] $UseSsl,
        [Parameter(Mandatory = $true)]
        [string] $SmtpServer,
        [Parameter(Mandatory = $false)]
        [int] $Port,
        [Parameter(Mandatory = $true, ParameterSetName = "LegacyAuth")]
        [pscredential] $Credential = $null,
        [Parameter(Mandatory = $false, ParameterSetName = "Token")]
        [string] $AccessToken = $null,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [string] $UserName,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [string] $ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth_app")]
        [string] $TenantId,
        [Parameter(Mandatory = $false)]
        [switch] $Force
    )

    [System.IO.StreamReader]$Script:reader
    [System.IO.StreamWriter]$Script:writer
    [int]$Script:responseCode = 0;
    [string]$Script:smtpResponse
    [string[]]$Script:sessionCapabilities
    [System.Collections.Generic.List[PSObject]]$Script:LogVar = @()

    # Verbose details for name resolution
    Write-Verbose "Resolving hostname to IP addresses..."
    $dns = (Resolve-DnsName -Name $smtpServer -QuickTimeout)
    $dns | ForEach-Object { if ($null -ne $_.IP4Address) { Write-Verbose $_.IP4Address } }
    $dns | ForEach-Object { if ($null -ne $_.IP6Address) { Write-Verbose $_.IP6Address } }

    if ($Port -eq 0) {
        # Set default port to 587
        $Port = 587
    }

    try {
        [bool]$authSuccess = $false

        # Use OAUTH if the client id was supplied
        if ($null -ne $ClientId -and $ClientId.Length -ne 0) {
            Connect
            # Check if dependency module exist
            Import-Module MSAL.PS -ErrorAction SilentlyContinue
            $module = Get-Module MSAL.PS
            if ($null -eq $module -or $module.Count -eq 0) {
                Write-Error "MSAL.PS module is required for obtaining an access token. Install the missing dependency."
                return
            }

            # Obtain an access token first
            $token = GetAccessToken
            if ($null -eq $token -or $token.Length -eq 0) {
                return;
            }
        
            $authSuccess = XOAUTH2Login($token.AccessToken)
        }
        # Else if no client id check if credentials are available and use legacy auth
        else {
            Connect
            if ($Credential.Length -ne 0) {
                # Legacy auth
                $authSuccess = AuthLogin
            }
        }
        # Send mail
        if ($authSuccess -eq $true) {
            SendMail
        }

        # If force switch true, send mail anyway if auth failed or no creds available
        if ($authSuccess -eq $false -and $Force -eq $true) {
            SendMail
        }
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
        Write-Verbose "Resources disposed."
        Write-Host -ForegroundColor Red "[Disconnected]"

        # Write log to file
        WriteFile
    }
}
function Connect() {
<<<<<<< Updated upstream
    Write-Host -ForegroundColor Yellow "[Connecting]" 
=======
    Write-Host -ForegroundColor Yellow "[Connecting]"
    $Script:LogVar += "Connecting to $SmtpServer"+":$Port"

>>>>>>> Stashed changes
    $Script:tcpClient = New-Object System.Net.Sockets.TcpClient;
    $Script:tcpClient.ReceiveTimeout = 10000
    $Script:tcpClient.SendTimeout = 10000

    $result = $Script:tcpClient.BeginConnect($SmtpServer, $Port, $null, $null)
    $result.AsyncWaitHandle.WaitOne(10000) | Out-Null

    if(!$Script:tcpClient.Connected)
    {
        Write-Error "Connection to remote host timed out after 10000 ms." -ErrorAction Stop
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
            SmtpCmd("STARTTLS");
            if ($Script:responseCode -eq 220) {
                WriteMessage("* Starting TLS negotation")
                $sslstream = New-Object System.Net.Security.SslStream::($Script:tcpClient.GetStream())
                $sslstream.AuthenticateAsClient($SmtpServer)

                $Script:writer = New-Object System.IO.StreamWriter::($sslstream)
                $Script:reader = New-Object System.IO.StreamReader::($sslstream)

                WriteMessage("* TLS negotiation completed." + " CipherAlgorithm:" + $sslstream.CipherAlgorithm + " TlsVersion:" + $sslstream.SslProtocol)
                WriteMessage("* RemoteCertificate: " + "<S>" + $sslstream.RemoteCertificate.Subject + "<I>" + $sslstream.RemoteCertificate.Issuer)

                $rawCert = "`n-----BEGIN CERTIFICATE-----"
                $rawCert += "`n" + [Convert]::ToBase64String($sslstream.RemoteCertificate.GetRawCertData())
                $rawCert += "`n-----END CERTIFICATE----- "

                Write-Verbose "Remote Certificate:"
                Write-Verbose $rawCert

                # Rediscover session capabilities
                SendEhlo;
            }
            else {
                Write-Error "Failed to start tls session with remote host."; 
            }
        }
        # STARTTLS verb not found
        else {
            Write-Error "Session capabilities do not support STARTTLS."
        }
    }
}
function ReadResponse() {
    # Clear any prior responses and response codes
    $Script:responseCode = -1;
    $Script:smtpResponse = $null;

    # Bail if not connected
    if ($Script:tcpClient.Connected -eq $false) {
        WriteMessage("Client is not connected.");
        return;
    }

    Write-Verbose "Reading stream..."
    $line = $reader.ReadLine();

    if ($null -eq $line) {
        return $responseCode;
    }

    $Script:smtpResponse += $line;

    # Parse response code
    $Script:responseCode = [System.Int32]::Parse($line.Substring(0, 3));

    # Read all lines
    while ($Script:reader.Peek() -gt 0) {
        $line = $Script:reader.ReadLine();
        if ($null -eq $line) {
            Write-Error("End of stream.");
        }
        $Script:smtpResponse += "," + $line.Substring(4);
    }

    WriteMessage("< " + $Script:smtpResponse);
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
        Write-Error "StreamWriter is null"
        return
    }

    $Script:writer.WriteLine($command);
    $Script:writer.Flush();

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
        SmtpCmd("AUTH LOGIN");

        if ($Script:responseCode -eq 334) {
            $message = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Script:smtpResponse.Substring(4))).ToLower();
            if ($message -eq "username:") {
                SmtpCmd ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credential.UserName)))
            }

            $message = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Script:smtpResponse.Substring(4))).ToLower();

            # If username accepted continue
            if (($Script:responseCode -eq 334) -and ($message -eq "password:")) {
                SmtpCmd ([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credential.GetNetworkCredential().Password))) -redactCmd $true
            }
            else {
                Write-Error "SMTP Authentication Failed. Invalid user name."
                return $false
            }
            if ($Script:responseCode -ne 235) {
                Write-Error "SMTP Authentication Failed. Check user name and password."
                return $false
            }

            return $true
        }
        else {
            Write-Error "Unexpected response code on AUTH LOGIN." 
        }
    }
    else {
        
        Write-Error "Session capabilities do not support AUTH LOGIN"
    }
    return $false
}
function XOAUTH2Login([string]$token) {
    if ($null -eq $token -or $token.Length -eq 0) {
        Write-Error "AccessToken is null or empty"
        return
    }
    # Build the token
    $authBlob = "user=" + $UserName + "$([char]0x01)auth=Bearer " + $token + "$([char]0x01)$([char]0x01)"

    if (ContainsCapability("XOAUTH2")) {
        SmtpCmd("AUTH XOAUTH2");

        if ($Script:responseCode -eq 334) {
            SmtpCmd([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($authBlob)))

            if ($Script:responseCode -eq 235) {
                return $true
            }
            else {
                return $false
            }
        }
        else {
            Write-Error "Unexpected response code." 
            return $false
        }
    }
    else {
        
        Write-Error "Session capabilities do not support AUTH XOAUTH2"
        return $false
    }
}
function GetAccessToken() {
    # Use supplied token instead if provided
    if ($AccessToken.Length -ne 0) {
        Write-Verbose "User supplied AccessToken. Not fetching new token."
        return $AccessToken
    }
    else {
        Write-Verbose "Obtaining an access token using MSAL.PS module"

        $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Interactive -Scope 'https://outlook.office365.com/Smtp.Send' -LoginHint $UserName
        if ($token.AccessToken.Length -eq 0) {
            Write-Error "No token was available in the token request result"
            return
        }

        return $token
    }
}
function SendMail() {
    SmtpCmd("MAIL FROM: <$From>")
    if ($Script:responseCode -ne 250) {
        Write-Error "Unexpected response code on MAIL FROM command."
        SmtpCmd("QUIT");
        return
    }

    SmtpCmd("RCPT TO: <$To>")
    if ($Script:responseCode -ne 250) {
        Write-Error "Unexpected response code on TO command."
        SmtpCmd("QUIT");
        return
    }

    $message = "From: `"$From`" <$From>"
    $message += "`nTo: `"$To`" <$To>"
    $message += "`nSubject: SMTP Client Submission Test"
    $message += "`nContentType: plain/text"
    $message += "`n"
    $message += "`nThis is a test message."

    $byteCount = [System.Text.Encoding]::ASCII.GetByteCount($message)
    $command = "BDAT $byteCount LAST"

    SmtpCmd($command)

    Write-Verbose "Writing message to stream..."
    $Script:writer.Write($message);
    $Script:writer.Flush();

    ReadResponse
    
    if ($Script:responseCode -ne 250) {
        Write-Error "Failed to submit message."
    }

    SmtpCmd("QUIT");
}
function WriteMessage($message) {
    # Format output
    $out = (Get-Date).ToUniversalTime().ToString() + " " + $message
    Write-Host $out

    # Save to variable for logging
    $Script:LogVar += $out
}
function WriteFile() {
    # Check path exist
    if ((Test-Path 'logs' -PathType Container) -eq $false) {
        New-Item -Path 'logs' -ItemType Directory -Force | Out-null
    }

    $filePath = (Get-Location).Path + "\logs\smtpdiag.log"
    Write-Host -ForegroundColor Green "Saved log file to:" $filePath

    $Script:LogVar += "---End of Session---"
    $Script:LogVar | Out-File -FilePath $filePath -Append -Force
}
Export-ModuleMember -Function Test-SmtpClientSubmission