## SmtpClientDiag
The project contains a PowerShell module that can be used to test SMTP Client Submission. The module will output the SMTP session to console and save to a log file.

The module supports both Basic (AUTH LOGIN) and OAuth (XOAUTH2) authentication. For modern authentication, you must install the MSAL.PS module to obtain a token.

## Getting Started
If using Modern Authentication, make sure you have followed the instructions in the document below before testing.

Link: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth

Execute the cmdlet below to install the module.

  Install-Module -Name SmtpClientDiag -MinimumVersion 1.0.0.13
  
## Examples: 

Submit mail without credentials.
> Test-SmtpClientSubmission -From \<FromAddress\> -To \<RecipientAddress\> -UseSsl -SmtpServer smtp.office365.com -Port 25 -Force

Submit mail using legacy authentication.

> Test-SmtpClientSubmission -From \<FromAddress\> -To \<RecipientAddress\> -UseSsl -SmtpServer smtp.office365.com -Port 587 -Credential \<PSCredential\>

Submit mail using modern authentication.

> Test-SmtpClientSubmission -From \<FromAddress\> -To \<RecipientAddress\> -UseSsl -SmtpServer smtp.office365.com -Port 587 -UserName \<MailboxSmtp\> -ClientId 9954180a-16f4-4683-aaaaaaaaaaaa -TenantId 1da8c747-60dd-4404-8418-aaaaaaaaaaaa

