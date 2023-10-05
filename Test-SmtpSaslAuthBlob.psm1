<#
 .Synopsis
  Diagnostic module for SMTP Sasl Auth Blob

 .Description
  Utility module for testing SMTP Sasl Auth Blob for common issues and misconfigurations.

 .Parameter EncodedAuthBlob
  Base64 encoded auth blob to test.

 .Example
   # Test an auth blob
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
#>
using module .\Utils.psm1
function Test-SmtpSaslAuthBlob() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$EncodedAuthBlob
    )

    $Script:BlobResult = [PSCustomObject] @{
        AuthBlobUserName        = $null
        AuthBlobToken           = $null
        OAuthTokenAudience      = $null
        OAuthTokenScopes        = $null
        OAuthTokenRoles         = $null
        OAuthTokenUpn           = $null
        OAuthTokenExpirationUtc = $null
        ApplicationId           = $null
        AppDisplayName          = $null
        IsAuthBlobValid         = $false
        IsAuthTokenValid        = $false
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

    # Check if 'auth' is present after 'user'
    if ($authIndex -eq -1) {
        Write-Verbose "Invalid Authblob. 'auth' not found in auth blob."
        Write-Error "Authblob is incorrectly formatted. Auth not found." -ErrorAction Stop
    }

    # Check if 'Bearer' is present after 'auth'
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
    $Script:BlobResult.OAuthTokenExpirationUtc = [System.DateTimeOffSet]::FromUnixTimeSeconds($token.exp).UtcDateTime
    $Script:BlobResult.ApplicationId = $token.appid
    $Script:BlobResult.AppDisplayName = $token.app_displayname

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

        # If delegated permission check if upn in token matches username in auth blob
        # Token can be valid but must be for the same user as the auth blob
        if (-not $isAppAuth) {
            if ($token.upn -ne $Script:BlobResult.AuthBlobUserName) {
                $tokenValid = $false
                Write-Verbose "UPN claim in token does not match username in auth blob. UPN claim:'$($token.upn)' Username:'$($Script:BlobResult.AuthBlobUserName)'."
                Write-Warning "UPN in authentication token and AuthBlob do not match."
            }
        }

        # If using client credential flow check the roles claim
        if ($isAppAuth) {
            Write-Verbose "Checking roles claim for SMTP.SendAsApp permission."
            if ([string]::IsNullOrEmpty($token.roles)) {
                $tokenValid = $false
                Write-Verbose "Roles claim is null or empty."
                Write-Warning "Required permission for SMTP Client Submission not found in token."
            }
            else{
                $permissions = $token.roles.Split()
                if (-not $permissions.Contains("SMTP.SendAsApp")) {
                    $tokenValid = $false
                    Write-Verbose "Invalid roles in token. Expected 'SMTP.SendAsApp' but found '$($token.roles)'."
                    Write-Warning "Required permission for SMTP Client Submission not found in token."
                }
            }
        }

        # Else check the scopes claim
        else {
            Write-Verbose "Checking scopes claim for SMTP.Send permission."
            if ([string]::IsNullOrEmpty($token.scp)){
                $tokenValid = $false
                Write-Verbose "Scopes claim is null or empty."
                Write-Warning "Required permission for SMTP Client Submission not found in token."
            }
            else{
                $permissions = $token.scp.Split()
                if (-not $permissions.Contains("SMTP.Send")) {
                    $tokenValid = $false
                    Write-Verbose "Invalid scope in token. Expected 'SMTP.Send' but found '$($token.scp)'."
                    Write-Warning "Required permission for SMTP Client Submission not found in token."
                }
            }
        }

        # Check if token is expired
        $currentDateTime = Get-Date

        if ($currentDateTime.ToUniversalTime() -gt $Script:BlobResult.OAuthTokenExpirationUtc) {
            $tokenValid = $false
            Write-Verbose "Token has expired. Token expiration date: '$tokenExpiration'. Current date: '$currentDateTime'."
            Write-Warning "Authentication token has expired."
        }
    }
    else {
        $tokenValid = $false
    }

    $Script:BlobResult.IsAuthTokenValid = $tokenValid
}
