using module .\Logger.psm1
Add-Type -AssemblyName System.IO
Add-Type -AssemblyName System.Net

class InternalSmtpClient {
    hidden [System.Net.Sockets.TcpClient]$TcpClient
    hidden [int]$TimeoutMs
    hidden [System.IO.StreamReader]$Reader
    hidden [System.IO.StreamWriter]$Writer
    hidden [string[]]$SessionCapabilities
    hidden [string]$LastSmtpResponse
    hidden [Logger]$Logger

    [int]$TimeoutSec = 60
    [int]$ResponseCode = -1

    InternalSmtpClient ([Logger]$logger) {
        $this.Logger = $logger
    }
    
    [void] Connect([string]$smtpServer, [int]$port, [bool]$useSsl, [bool]$acceptUntrustedCertificates, [System.Security.Cryptography.X509Certificates.X509Certificate]$clientCertificate, $enabledSslProtocols) {
        [bool]$useClientCert = $false
        $this.TimeoutMs = $this.TimeoutSec * 1000

        if ($null -ne $clientCertificate) {
            $useClientCert = $true
        }

        $this.logger.LogMessage("# Tcp Client Timeout Settings", "Information", $true, $true)
        $this.logger.LogMessage("TcpClientReceiveTimeOut: $($this.TimeoutSec)s", "Information", $true, $true)
        $this.logger.LogMessage("TcpClientSendTimeOut: $($this.TimeoutSec)s", "Information", $true, $true)
        $this.logger.LogMessage("", "Information", $true, $true)
        $this.logger.LogMessage("[Connecting to $SmtpServer" + ":$Port]", "Information", "Yellow", $false, $true)

        $this.TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
        $this.TcpClient.ReceiveTimeout = $this.TimeoutMs
        $this.TcpClient.SendTimeout = $this.TimeoutMs

        $result = $this.TcpClient.BeginConnect($SmtpServer, $Port, $null, $null)
        $result.AsyncWaitHandle.WaitOne($this.TimeoutMs) | Out-Null
        $this.TcpClient.EndConnect($result)

        if (-not $this.TcpClient.Connected) {
            # If not connected exception *should* be thrown in EndConnect()
            $this.Logger.LogError("Connection to remote host $($SmtpServer + ":$Port") failed!")
        }

        $this.Logger.LogMessage("[Connected]", "Information", "Green", $false, $true)

        $this.Reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($this.TcpClient.GetStream(), [System.Text.Encoding]::ASCII)
        $this.Writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList ($this.TcpClient.GetStream(), [System.Text.Encoding]::ASCII)

        $this.ReadResponse($false)
        $this.SendEhlo()

        if ($useSsl) {
            $this.Logger.LogMessage("Starting TLS...", "Verbose", $false, $true)
            if ($this.SessionCapabilities.Contains("STARTTLS")) {
                $this.SmtpCmd("STARTTLS")
                if ($this.ResponseCode -eq 220) {
                    $this.Logger.LogMessage("* Starting TLS negotiation")
                    if ($AcceptUntrustedCertificates) {
                        $this.Logger.LogMessage("Ignoring certificate validation results.", "Verbose", $false, $true)
                        $sslstream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList ($this.TcpClient.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
                    }
                    else {
                        $sslstream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList ($this.TcpClient.GetStream())
                    }
                    $certcol = $null

                    if ($useClientCert) {
                        $certcol = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509CertificateCollection
                        $certcol.Add($clientCertificate)
                    }
                    <# 
                        If enabledSslProtocols is null, don't specify an ssl protocol to use.
                        AuthenticateAsClient will use the OS preferred TLS version
                        This avoids ArgumentException when using NONE and OS settings disable default tls versions.

                        https://referencesource.microsoft.com/#System/net/System/Net/SecureProtocols/_SslState.cs,164
                    #>
                    if ($null -eq $enabledSslProtocols) {
                        $sslstream.AuthenticateAsClient($SmtpServer, $certcol, $true)
                    }
                    else {
                        $sslstream.AuthenticateAsClient($SmtpServer, $certcol, $enabledSslProtocols, $true)
                    }

                    $this.Writer = New-Object -TypeName System.IO.StreamWriter -ArgumentList ($sslstream, [System.Text.Encoding]::ASCII)
                    $this.Reader = New-Object -TypeName System.IO.StreamReader -ArgumentList ($sslstream, [System.Text.Encoding]::ASCII)

                    $this.Logger.LogMessage("* TLS negotiation completed. IgnoreCertValidation:$AcceptUntrustedCertificates CipherAlgorithm:$($sslstream.CipherAlgorithm) HashAlgorithm:$($sslstream.HashAlgorithm) TlsVersion:$($sslstream.SslProtocol)")
                    $this.Logger.LogMessage("* RemoteCertificate: '<S>$($sslstream.RemoteCertificate.Subject)<I>$($sslstream.RemoteCertificate.Issuer)' NotBefore:$($sslstream.RemoteCertificate.GetEffectiveDateString()) NotAfter:$($sslstream.RemoteCertificate.GetExpirationDateString())")
                    if ($useClientCert) {
                        $this.Logger.LogMessage("* ClientCertificate: '<S>$($sslstream.LocalCertificate.Subject)<I>$($sslstream.LocalCertificate.Issuer)' NotBefore:$($sslstream.LocalCertificate.GetEffectiveDateString()) NotAfter:$($sslstream.LocalCertificate.GetExpirationDateString())")
                    }

                    # Warn if using unsupported versions of TLS
                    # Intentionally not setting TLS to 1.2 or greater to expose default TLS behavior
                    if ($sslstream.SslProtocol -eq "Tls" -or $sslstream.SslProtocol -eq "Tls11") {
                        Write-Warning "TLS version is either 1.0 or 1.1. Consider enabling TLS 1.2 or greater."
                    }

                    $rawCert = "`n-----BEGIN CERTIFICATE-----"
                    $rawCert += "`n" + [Convert]::ToBase64String($sslstream.RemoteCertificate.GetRawCertData(), [System.Base64FormattingOptions]::InsertLineBreaks)
                    $rawCert += "`n-----END CERTIFICATE----- "

                    $this.Logger.LogMessage("Remote Certificate:", "Verbose", $false, $true)
                    $this.Logger.LogMessage($rawCert, "Verbose", $false, $true)

                    # Rediscover session capabilities
                    $this.SendEhlo()
                }
                else {
                    throw "Failed to start tls session with remote host."
                }
            }
            # STARTTLS verb not found
            else {
                throw "Session capabilities do not support STARTTLS."
            }
        }
    }

    [void] ReadResponse([bool]$readAllLines) {
        $this.ResponseCode = - 1
        $resp = @()

        # Bail if not connected
        if (-not $this.TcpClient.Connected) {
            throw "Client is not connected."
        }

        $line = $this.Reader.ReadLine()
        $resp += $line

        # Parse response code
        $this.ResponseCode = [System.Int32]::Parse($line.Substring(0, 3))

        if ($readAllLines){
            while ($line -like "250-*") {
                Write-Debug "StreamReader: Reading more lines..."
                $line = $this.Reader.ReadLine()
                # Truncate response code and join all server capabilities
                $resp += $line.Substring(4)
            }
            $resp = $resp -join ','            
        }

        $this.LastSmtpResponse = $resp
        $this.Logger.LogMessage("< " + $resp)
    }

    [void] SendEhlo() {
        $this.SmtpCmd("EHLO " + ([System.Environment]::MachineName))

        if ($this.ResponseCode -ne 250) {
            throw "Unexpected response on EHLO command. Response Code:$($this.ResponseCode)"
        }

        foreach ($c in $this.LastSmtpResponse.Split(',') | Where-Object { ($_) -and ($_ -notcontains "250") }){
            $this.SessionCapabilities += $c.Replace("250-", "").Trim()
        }
    }

    [void] SmtpCmd([string]$command) {
        $this.SmtpCmd($command, $false)
    }

    [void] SmtpCmd([string]$command, [bool]$redactCmd) {
        if ($redactCmd) {
            $this.Logger.LogMessage("Sending command: *REDACTED*", "Verbose", $false, $true)
            $this.Logger.LogMessage("> *REDACTED*")
        }
        else {
            $this.Logger.LogMessage("Sending command: $command", "Verbose", $false, $true)
            $this.Logger.LogMessage("> " + $command)
        }

        $this.Writer.WriteLine($command)
        $this.Writer.Flush()

        if (($command -ne "QUIT") -and (!$command.StartsWith("BDAT"))) {
            $this.ReadResponse($false)
        }

        if ($command -like "EHLO *") {
            $this.ReadResponse($true)
        }
    }

    [bool] ContainsCapability([string] $c) {
        foreach ($cap in $this.SessionCapabilities) {
            if ($cap.ToLower().Contains($c.ToLower())) {
                return $true
            }
        }

        return $false
    }

    [bool] AuthLogin([pscredential]$Credential) {
        if ($this.ContainsCapability("AUTH LOGIN")) {
            $this.SmtpCmd("AUTH LOGIN")

            if ($this.ResponseCode -eq 334) {
                $message = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($this.LastSmtpResponse.Substring(4))).ToLower()
                if ($message -eq "username:") {
                    $this.SmtpCmd([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credential.UserName)))
                }

                # Decode the response
                $message = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($this.LastSmtpResponse.Substring(4))).ToLower()

                # If username accepted continue
                if (($this.ResponseCode -eq 334) -and ($message -eq "password:")) {
                    $this.SmtpCmd([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credential.GetNetworkCredential().Password)), $true)
                }
                else {
                    $this.Logger.LogError("SMTP Authentication Failed. Invalid user name.")
                    return $false
                }
                if ($this.ResponseCode -eq 535 -and $($this.LastSmtpResponse.Substring(4)).StartsWith("5.7.139")) {
                    $this.Logger.LogError("SMTP Authentication Failed. Basic authentication disabled or blocked by policy.")
                    return $false
                }
                if ($this.ResponseCode -eq 421) {
                    $this.Logger.LogError("SMTP Authentication Failed. Check your TLS version is at least 1.2.")
                    return $false
                }
                if ($this.ResponseCode -ne 235) {
                    $this.Logger.LogError("SMTP Authentication Failed. Check user name and password.")
                    return $false
                }

                return $true
            }
            else {
                $this.Logger.LogError("Unexpected response code on AUTH LOGIN.")
            }
        }
        else {
            $this.Logger.LogError("Session capabilities do not support AUTH LOGIN")
        }
        return $false
    }

    [bool] XOAUTH2Login([string]$userName, [string]$token) {
        if ([System.String]::IsNullOrEmpty($token)) {
            $this.Logger.LogError("AccessToken is null or empty")
            return $false
        }
        # Build the auth blob
        $authBlob = "user=" + $UserName + "$([char]0x01)auth=Bearer " + $token + "$([char]0x01)$([char]0x01)"

        if ($this.ContainsCapability("XOAUTH2")) {
            $this.SmtpCmd("AUTH XOAUTH2")

            if ($this.ResponseCode -eq 334) {
                $this.SmtpCmd([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($authBlob)))

                if ($this.ResponseCode -eq 421) {
                    $this.Logger.LogError("SMTP Authentication Failed. Check your TLS version is at least 1.2.")
                    return $false
                }
                if ($this.ResponseCode -eq 235) {
                    return $true
                }
                else {
                    $this.Logger.LogError("SMTP Authentication Failed. Check your OAUTH token is valid.")
                    return $false
                }
            }
            else {
                $this.Logger.LogError("Unexpected response code on AUTH XOAUTH2.")
                return $false
            }
        }
        else {
            $this.Logger.LogError("Session capabilities do not support AUTH XOAUTH2.")
            return $false
        }
    }

    [void] SendMail([string]$From, [string]$To) {
        $this.SmtpCmd("MAIL FROM: <$From>")
        if ($this.ResponseCode -ne 250) {
            $this.Logger.LogError("Unexpected response code on MAIL FROM command.")
            $this.SmtpCmd("QUIT")
            return
        }

        $this.SmtpCmd("RCPT TO: <$To>")
        if ($this.ResponseCode -ne 250) {
            $this.Logger.LogError("Unexpected response code on RCPT TO command.")
            $this.SmtpCmd("QUIT")
            return
        }

        $message = "From: `"$From`" <$From>"
        $message += "`nTo: `"$To`" <$To>"
        $message += "`nSubject: SMTP Client Submission Test"
        $message += "`nContent-Type: text/plain"
        $message += "`n"
        $message += "`nThis is a test message."

        # Check if server supports CHUNKING and send using BDAT command
        if ($this.ContainsCapability("CHUNKING")) {
            $this.SendContentUsingBdat($message)
        }
        # If capability not found send using DATA command
        else {
            $this.SendContentUsingData($message)
        }
        $this.ReadResponse($false)

        if ($this.ResponseCode -eq 430 -and $($this.LastSmtpResponse.Substring(4)).StartsWith("4.2.0 STOREDRV; mailbox logon failure;")) {
            $this.Logger.LogError("Failed to submit message. Verify that the authenticated user or application has the correct permission to logon to the mailbox.")
        }
        elseif ($this.ResponseCode -ne 250) {
            $this.Logger.LogError("Failed to submit message.")
        }

        $this.SmtpCmd("QUIT")
    }

    [void] SendContentUsingBdat($message)
    {
        $byteCount = [System.Text.Encoding]::ASCII.GetByteCount($message)
        $command = "BDAT $byteCount LAST"

        $this.SmtpCmd($command)
        $this.Logger.LogMessage("Writing message to stream...", "Verbose", $false, $true)
        $this.Writer.Write($message)
        $this.Writer.Flush()
    }

    [void] SendContentUsingData($message)
    {
        $command = "DATA"

        $this.SmtpCmd($command)
        $this.Logger.LogMessage("Writing message to stream...", "Verbose", $false, $true)
        $this.Writer.Write($message)
        $this.Logger.LogMessage("Writing terminator '<CRLF>.<CRLF>' to stream.", "Verbose", $false, $true)
        $this.Writer.Write("`r`n.`r`n")
        $this.Writer.Flush()
    }

    [void] DisposeResources() {
        if ($this.Writer) {
            $this.Writer.Dispose()
        }
        if ($this.Reader) {
            $this.Reader.Dispose()
        }
        if ($this.TcpClient) {
            $this.TcpClient.Dispose()
        }
    }
}
