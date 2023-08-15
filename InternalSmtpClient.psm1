using module .\Logger.psm1
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

    [void] Connect([string]$smtpServer, [int]$port, [bool]$useSsl, [bool]$acceptUntrustedCertificates, [System.Security.Cryptography.X509Certificates.X509Certificate]$clientCertificate) {
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

        $this.TcpClient = New-Object System.Net.Sockets.TcpClient
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

        $this.Reader = New-Object System.IO.StreamReader::($this.TcpClient.GetStream(), [System.Text.Encoding]::ASCII)
        $this.Writer = New-Object System.IO.StreamWriter::($this.TcpClient.GetStream(), [System.Text.Encoding]::ASCII)

        $this.ReadResponse()
        $this.SendEhlo()

        if ($useSsl) {
            $this.Logger.LogMessage("Starting TLS...", "Verbose", $false, $true)
            if ($this.SessionCapabilities.Contains("STARTTLS")) {
                $this.SmtpCmd("STARTTLS")
                if ($this.ResponseCode -eq 220) {
                    $this.Logger.LogMessage("* Starting TLS negotation")
                    if ($AcceptUntrustedCertificates) {
                        $this.Logger.LogMessage("Ignoring certificate validation results.", "Verbose", $false, $true)
                        $sslstream = New-Object System.Net.Security.SslStream::($this.TcpClient.GetStream(), $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]))
                    }
                    else {
                        $sslstream = New-Object System.Net.Security.SslStream::($this.TcpClient.GetStream())
                    }

                    if ($useClientCert) {
                        $certcol = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
                        $certcol.Add($clientCertificate)
                        $sslstream.AuthenticateAsClient($SmtpServer, $certcol, $true)
                    }
                    else {
                        $sslstream.AuthenticateAsClient($SmtpServer)
                    }

                    $this.Writer = New-Object System.IO.StreamWriter::($sslstream, [System.Text.Encoding]::ASCII)
                    $this.Reader = New-Object System.IO.StreamReader::($sslstream, [System.Text.Encoding]::ASCII)

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

    [void] ReadResponse() {
        $this.ResponseCode = - 1
        $resp = @()

        # Bail if not connected
        if (-not $this.TcpClient.Connected) {
            throw "Client is not connected."
        }

        $line = $this.Reader.ReadLine()

        if ([System.String]::IsNullOrEmpty($line)) {
            return
        }

        $resp += $line

        # Parse response code
        $this.ResponseCode = [System.Int32]::Parse($line.Substring(0, 3))

        # Read all lines
        while ($this.Reader.Peek() -gt 0) {
            Write-Debug "StreamReader: Reading more lines..."
            $line = $this.Reader.ReadLine()
            if ([System.String]::IsNullOrEmpty($line)) {
                Write-Error -Message "End of stream."
            }

            # If more lines, truncate response code
            $resp += $line.Substring(4)
        }
        $this.LastSmtpResponse = $resp -join ','
        $this.Logger.LogMessage("< " + $resp)
    }

    [void] SendEhlo() {
        $this.SmtpCmd("EHLO " + ([System.Environment]::MachineName))

        if ($this.ResponseCode -ne 250) {
            throw "Unexpected response on EHLO command. Response Code:$($this.ResponseCode)"
        }

        $lines = $this.LastSmtpResponse.Split(',') | Where-Object { ($_) -and ($_ -notcontains "250") }
        $this.SessionCapabilities = $lines
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
            $this.ReadResponse()
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

        # Script does not check for chuncking capability as it is not meant to support all MTAs
        # BDAT is preferred over DATA command
        $byteCount = [System.Text.Encoding]::ASCII.GetByteCount($message)
        $command = "BDAT $byteCount LAST"

        $this.SmtpCmd($command)
        $this.Logger.LogMessage("Writing message to stream...", "Verbose", $false, $true)
        $this.Writer.Write($message)
        $this.Writer.Flush()
        $this.ReadResponse()

        if ($this.ResponseCode -ne 250) {
            $this.Logger.LogError("Failed to submit message.")
        }

        $this.SmtpCmd("QUIT")
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
# SIG # Begin signature block
# MIIm8wYJKoZIhvcNAQcCoIIm5DCCJuACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUWTq1jHRz121ObSc9yKTsl5v
# 7LKggiCbMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
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
# r6n+lB3nYxs6hlZ4TjCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTla
# MEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UE
# AxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIV
# WMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9Yr
# IBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5x
# XsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4
# KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUd
# vJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZ
# BzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02ke
# fGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1
# x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhv
# ltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPs
# CvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T
# 5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1P
# ijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09
# SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5
# j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXT
# UOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08z
# jdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9N
# UvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg2
# 1Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44Owde
# OVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZr
# uhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7
# KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywG
# Ru9BHvDwX+Db2a2QgESvgBBBijCCBtowggTCoAMCAQICEArx8amB0NDrO6HOBWrh
# kz4wDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2ln
# bmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMTAeFw0yMzAzMTEwMDAwMDBaFw0y
# NTAzMTMyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEPMA0G
# A1UEBxMGSXJ2aW5nMRgwFgYDVQQKEw9SaWNoYXJkIEZhamFyZG8xGDAWBgNVBAMT
# D1JpY2hhcmQgRmFqYXJkbzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGB
# AMMH8sXjUbUrpEqDBEM5vtduT1uEurj0xmp8SeNNCZvipsc7rZ4d6sK7gpc9fsZk
# wn6BVeQAip9hBA03xmNK0sBdOFzAsk1mHSvZbFYifv7fb9bHDQUivKfykIaZgZmD
# /tD+vn/Fg1qUOv6/fMhB+H4zbi9Ln8xJy9LokGJhXNjwNa1MXfNW+QTKah3Be+2D
# AdbfkmEjfH9kIfBQXmiaXRhvy0SrMDn63rGk1nMBnO+7fvDgDhl9/zI8cZBPHcn/
# kyl/dKi3RgmuFxRPuOu4V3jZDM0z+HVchuBg/WTjOKJhAm8WnN8QJWH9o0Z/Xh+L
# jGm+AZpOloeXSHBEUN/3xEstblm7qELU/QvdLqjtER57RgEKvD6orKFEKDXQXqtO
# nTepNPBxmk5qxD0qvxTBpNJc5fxkrXjPAO7bM/A9E5vTNA7yJN7qRddaq91QQR86
# etCx+RJG9i1FFlmjvKDshXs8c17uvDR3ry96FXh9YwQG3IwKfvf/1pkl5qJNXdWZ
# vQIDAQABo4ICAzCCAf8wHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIw
# HQYDVR0OBBYEFG6ItulYwbKWmNAlQK2JcPHPUGo0MA4GA1UdDwEB/wQEAwIHgDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JT
# QTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0
# MjAyMUNBMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEFBQcCARYb
# aHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGUBggrBgEFBQcBAQSBhzCBhDAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAC
# hlBodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRD
# b2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNydDAJBgNVHRMEAjAAMA0G
# CSqGSIb3DQEBCwUAA4ICAQBrSBP6l3VUVEKOQA+58A2z8gp48suJ7pfcFdtQpWKH
# Rjq0V61+n+1Pgr2/efFmtExY0fd97j/zwbdLAk9kqAS4jYuR4Wk1di42mED1lQki
# ROdUFKfN7zq2LJpKC5WHCvsE5Szgoe5Kq7b8TLyVSf2Ulpcsen9qzQ1ZZcSDmVIf
# uiGkGEQ4fakhcxxL9Eho48fwepZnpAr0kQ7/SQVN9Mpt4UkVaRUVKrQkjTJHxW1D
# GTaKwUb2xRMtnW/bj4EScHAN9JYIjr5UptCUyg5RFZn1fnUHtq61kDdwRqA/G+wg
# lgWAUWmar9pGKO7rc07iF8iqIPysrMVz8CWnnkZXfJJ6bw5JeAine5GTQ0Ryf2P+
# PF9RyIQSEp7I7uDBWXVIBiint9PIC3z6fkHKsVA7W4wx2facvTCDG+KmnnGZ0EqI
# uw39ne2tRWCWObKqs3LsELN9sdoi43/OhF/Qj60u3S+of+EapwxUuQuoVhE8tHFN
# pkukENJ6K3SUWSG37Rj1bylpRqgILHGhsUKSCtTCiuB615s4cT0JzXUhuiz6smoZ
# ql+Cfy/A7BIvfZU6Spucft4Z2gm4e+o9sG/3qTQSRDIB61Hq92GeEOvNx780E9Rp
# 9iR2/F5ggsYxQQ3hQxNQfGFQGNA21OckIN2P7TayxjNmvKa1fGh61VYd6XqsUlzI
# +jGCBcIwggW+AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmlu
# ZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQCvHxqYHQ0Os7oc4FauGTPjAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQU7is/vFDpX43+yM7KVYzqMAffbpowDQYJKoZIhvcNAQEBBQAE
# ggGAdvfLoqA+fCL2z83TVdU00DTQONdbhWQzL2lS7glkBuWO6Amp9QdfqGdS+vN6
# ebkjLd6DqymPmLCMSU0eTh3E/g+fjuFtEagp6jWaFp2BorlL7Q1iHcuv4zNUODLi
# GKG74pgUcb3yHYzthpbazjbKmQUZYM5blVGnJI5cZ8SGRnVySD7ALB5pfXGPWTUT
# KyUwEX4a4qmLuEnAyijnlb5xKzFB4gJW+XDGW+yHxON0N+KBAr4ls3iNMfJA00QX
# 1uuqiAAFdGTetcmGkpIhrxKgr84chbKINSmkvO6jZKVYgezcazqE1T0sFk/4UGFf
# npXaZM/EwuNSBSaL5fA871hJczUHizKd8YDj5PWXBaP9UQzSLf6FWPq/42ZEHqFD
# oNHw5LKh5AxAfolxYGSYmcMi7D+3VYW2u4A05IFCv9cf6r4OtGJS2f2g45lJVhpB
# MfHmNao06bQ9V1Ry8mu1DtG5BXPeUzK98d91VqBccAiYvq2OQ6PejOpf0Tup/mcG
# moyRoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQBUSv85Sd
# CDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG
# 9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMDgxNTIxMjMxOFowLwYJKoZIhvcNAQkE
# MSIEIEBUrwK+04MFuWq7vzG+9iOedWA3c6f43P6/i/EX6Hy9MA0GCSqGSIb3DQEB
# AQUABIICADxrQLugZHDFAhXD4zJSoIKTrtuqpQVYFI68LLMFSAlwe54/Z8b1X3sr
# PddQHDZYAIa/qwvJce0M8MapK2YtgM6FRGyWNwZB6RZUyXXCWvQGnjROAxzpUT3t
# r7rAQdYeoY3FyeV9M+iIy0JWmgU0INexl6qodctQk9TOIt5dCnoT0G/sCHfYx6qu
# NNNaOTnfZcNqUiFGExYpZYHIBPGjVeK/1TqxP2GEzQQOxkgI6t7MZe3ORwFUNonB
# I3GvAKIVa1pvCpsWFC15OFFZQd2u5egB5FpUhraQaX8rh18DU5o3RxmSJJtrQiuq
# 2pPdNFXdbSCFOj6tOklJt7JJBMH+DZPdpENrElLdIEJbMAmhDd9IcSk5YFmAtkks
# CJBAiYkv6KXuwKYiAJdqa5otItkrKyetd9Nm9RbElFVoIK3DbQ+RUSRbTMlAYN8w
# /F+gZSEDI1Re9Z6uTkoQfMiFCzej44T/pDVgmCRUApUEeoxL6+PxRPylieiss1If
# 4SqFx5fBO0wkwjG8++KRWR9BJgI3S+9jol7B9839R1oTTtgKpKyo66O1pfk8YSmg
# oqQ3bBWVR6aCPeVJGnuWYii3G6ozzmSJ8aWGGJB0WNo0OlkEq7jIjczOxJzhjL7D
# 0P0dS0s2KyI7GLxkp1dwb3vtkuWREk1W7iKI+SdZMMPT2ubEZ1ZS
# SIG # End signature block
