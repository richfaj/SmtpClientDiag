# SmtpClientDiag

The project contains a PowerShell module that can be used to test SMTP Client Submission with Office 365. The module will output the SMTP session to console and save to a log file.

The module supports both Basic (AUTH LOGIN) and OAuth (XOAUTH2) authentication. For modern authentication, you must install the MSAL.PS module to obtain a token. For issues, please report the problem using the issues tab in Github.

## Getting Started

If using Modern Authentication, make sure you have followed the instructions in the document below before testing.

Link: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth

Execute the cmdlet below to install the module.

```PowerShell
Install-Module -Name SmtpClientDiag -MinimumVersion 1.4.0.5 -Scope CurrentUser
```

If you receive an error that the module cannot be found after installation, you may not have access to the location where the module is installed. Alternatively, you can install the module to `AllUsers` scope which will require elevation to install.

```PowerShell
Install-Module -Name SmtpClientDiag -MinimumVersion 1.4.0.5 -Scope AllUsers
```

[![PSGallery Version](https://img.shields.io/powershellgallery/v/SmtpClientDiag.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/SmtpClientDiag)

## Examples

Submit mail without credentials.

```PowerShell
Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.contoso.com -Port 25 -Force
```

Submit mail using legacy authentication.

```PowerShell
Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.contoso.com -Port 587 -Credential <PSCredential>
```

Submit mail using modern authentication (Delegation Authentication).

```PowerShell
Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.contoso.com -Port 587 -UserName <MailboxSmtp> -ClientId 9954180a-16f4-4683-aaaaaaaaaaaa -TenantId 1da8c747-60dd-4404-8418-aaaaaaaaaaaa
```

Submit mail using modern authentication (Application Authentication).

```PowerShell
Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.contoso.com -Port 587 -UserName <MailboxSmtp> -ClientId 9954180a-16f4-4683-aaaaaaaaaaaa -TenantId 1da8c747-60dd-4404-8418-aaaaaaaaaaaa -ClientSecret <SecureString>
```

Submit mail using your own application generated access token.

```PowerShell
Test-SmtpClientSubmission -From <FromAddress> -To <RecipientAddress> -UseSsl -SmtpServer smtp.contoso.com -Port 587 -UserName <MailboxSmtp> -AccessToken <YourAccessToken>
```

## Optional parameters

> -LogPath

Specify a custom path instead of the default working directory

> -AccessToken

Supply your own token. Can be used to test the token generated by your application or if using a different authentication flow. 

> -TimeoutSec

Use an alternative timeout value other than the default of 60s. Can be used if the remote MTA takes longer to process the SMTP command.

> -AcceptUntrustedCertificates

Ignore certificate validation results and allows the use of untrusted certificates.

> -TlsVersion

Specify the TLS version to use. Your machine must support the TLS version specified.

## Test-SmtpSaslAuthBlob

This function will check the auth blob for common issues that will cause authentication issues.

* Auth blob is in the correct format
* Auth blob contains null values or incorrect characters
* Check OAuth token for correct audience
* Check OAuth token for correct permissions

This function __does not__ validate the signature or expiration of your OAuth token against Entra Id (formerly Azure AD).

## Example

Test SMTP SASL Auth Blob.

```PowerShell
Test-SmtpSaslAuthBlob -EncodedAuthBlob 'dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==' -Verbose

AuthBlobUserName        : someuser@example.com
AuthBlobToken           : dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==
OAuthTokenAudience      : https://outlook.office.com
OAuthTokenScopes        : SMTP.Send
OAuthTokenRoles         :
OAuthTokenUpn           : someuser@example.com
OAuthTokenExpirationUtc : 01/01/1970 12:00:00 AM
ApplicationId           : 9954180a-16f4-4683-aaaaaaaaaaaa
AppDisplayName          : My OAuth SMTP Application
IsAuthBlobValid         : True
IsAuthTokenValid        : True
```

_Signed version available in PSGallery_