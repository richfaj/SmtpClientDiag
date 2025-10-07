<#
 .Synopsis
  Diagnostic module for SMTP SASL Auth Blob

 .Description
  Utility module for testing SMTP SASL Auth Blob for common issues and misconfigurations.
  Validates SASL XOAUTH2 authentication blobs and their embedded OAuth tokens.

 .Parameter EncodedAuthBlob
  Base64 encoded SASL XOAUTH2 auth blob to test.
  Expected format when decoded: user=username^Aauth=Bearer token^A^A
  Where ^A represents the ASCII control character 0x01

  .Parameter RbacEnabledApplication
  Switch to indicate if RBAC enforcement is enabled for application authentication.

 .Example
   # Test an auth blob
   Test-SmtpSaslAuthBlob -EncodedAuthBlob 'dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==' -Verbose

    AuthBlobUserName        : someuser@example.com
    AuthBlobToken           : eyJ0eXAiOiJKV1QiLCJub25jZSI6IlItWW...
    OAuthTokenAudience      : https://outlook.office.com
    OAuthTokenScopes        : SMTP.Send
    OAuthTokenRoles         :
    OAuthTokenUpn           : someuser@example.com
    OAuthTokenExpirationUtc : 01/01/1970 12:00:00 AM
    ApplicationId           : 9954180a-16f4-4683-aaaaaaaaaaaa
    AppDisplayName          : My OAuth SMTP Application
    IsAuthBlobValid         : True
    IsAuthTokenValid        : True

 .Notes
  The SASL XOAUTH2 mechanism format specification:
  base64("user=" + userName + "^Aauth=Bearer " + accessToken + "^A^A")
  Where ^A is the ASCII control character 0x01 (SOH - Start of Heading)
#>

using module .\Utils.psm1

# Constants for SASL blob validation
$script:SASL_CONTROL_CHAR = [char]0x01
$script:SASL_USER_PREFIX = "user="
$script:SASL_AUTH_PREFIX = "auth="
$script:SASL_BEARER_PREFIX = "Bearer "
$script:SASL_USER_PREFIX_LENGTH = $script:SASL_USER_PREFIX.Length
$script:SASL_AUTH_PREFIX_LENGTH = $script:SASL_AUTH_PREFIX.Length
$script:SASL_BEARER_PREFIX_LENGTH = $script:SASL_BEARER_PREFIX.Length

# Flag if RBAC enforcement is enabled for application authentication
$script:RbacEnabled = $false

function Test-SmtpSaslAuthBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$EncodedAuthBlob,
        [Parameter(Mandatory = $false)]
        [bool]$RbacEnabledApplication
    )

    [bool]$script:RbacEnabled = $RbacEnabledApplication

    if ($script:RbacEnabled) {
        Write-Verbose "RBAC enforcement for application authentication is enabled."
    }
    # Initialize result object
    $result = [PSCustomObject]@{
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

    # Validate input parameter
    if ([string]::IsNullOrEmpty($EncodedAuthBlob)) {
        Write-Error "AuthBlob is null or empty. Please supply a value to test." -ErrorAction Stop
    }

    try {
        # Decode and validate the SASL blob structure
        $decodedAuthBlob = ConvertFrom-EncodedSaslBlob -EncodedAuthBlob $EncodedAuthBlob
        $parsedBlob = ConvertFrom-SaslAuthBlob -DecodedBlob $decodedAuthBlob

        # Extract user and token information
        $result.AuthBlobUserName = $parsedBlob.UserName
        $result.AuthBlobToken = $parsedBlob.AccessToken

        # Validate the OAuth token
        Test-AccessTokenStructure -AccessToken $result.AuthBlobToken -Result $result -UserName $result.AuthBlobUserName

        # Mark blob as valid if we reach here
        $result.IsAuthBlobValid = $true

        Write-Verbose "SASL auth blob validation completed successfully"
        return $result
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Stop
    }
}

function ConvertFrom-EncodedSaslBlob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EncodedAuthBlob
    )

    try {
        $decodedBlob = DecodeBase64Value($EncodedAuthBlob)
        Write-Verbose "Successfully decoded SASL auth blob"
        return $decodedBlob
    }
    catch {
        Write-Verbose "Failed to decode auth blob: $EncodedAuthBlob"
        throw "AuthBlob is not a valid base64 encoded string. Check your input and try again."
    }
}

function ConvertFrom-SaslAuthBlob {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DecodedBlob
    )

    Write-Verbose "Parsing SASL auth blob structure"

    # Get key indices in the blob
    $userIndex = $DecodedBlob.IndexOf($script:SASL_USER_PREFIX)
    $authIndex = $DecodedBlob.IndexOf($script:SASL_AUTH_PREFIX)
    $bearerIndex = $DecodedBlob.IndexOf($script:SASL_BEARER_PREFIX)

    # Validate SASL blob structure
    $charArray = $DecodedBlob.ToCharArray()

    # Validate 'user=' is at the beginning
    if ($userIndex -ne 0) {
        Write-Verbose "Invalid SASL blob. Expected 'user=' at index 0. Found at index: $userIndex"
        throw "SASL auth blob is incorrectly formatted. 'user=' parameter not found in correct position."
    }

    # Validate 'auth=' is present
    if ($authIndex -eq -1) {
        Write-Verbose "Invalid SASL blob. 'auth=' not found in blob."
        throw "SASL auth blob is incorrectly formatted. 'auth=' parameter not found in blob."
    }

    # Validate 'Bearer ' is present after 'auth='
    if ($bearerIndex -eq -1 -or $bearerIndex -lt $authIndex) {
        Write-Verbose "Invalid SASL blob. 'Bearer ' not found or not in correct position. Bearer index: $bearerIndex"
        throw "SASL auth blob is incorrectly formatted. 'Bearer ' not found in expected position."
    }

    # Validate control character before 'auth='
    if ($authIndex -eq 0 -or $charArray[$authIndex - 1] -ne $script:SASL_CONTROL_CHAR) {
        if ($authIndex -gt 0) {
            $actualChar = GetCharHexValue($charArray[$authIndex - 1])
            Write-Verbose "Invalid SASL blob. Expected control character 0x01 before 'auth=' but found: 0x$actualChar"
        }
        else {
            Write-Verbose "Invalid SASL blob. Control character 0x01 not found before 'auth='."
        }
        throw "SASL auth blob is incorrectly formatted. Missing control character (0x01) before 'auth='."
    }

    # Validate control characters at the end (should be ^A^A)
    if ($charArray.Length -lt 2 -or
        $charArray[-1] -ne $script:SASL_CONTROL_CHAR -or
        $charArray[-2] -ne $script:SASL_CONTROL_CHAR) {
        $endChars = if ($charArray.Length -ge 2) {
            "0x$(GetCharHexValue($charArray[-2]))0x$(GetCharHexValue($charArray[-1]))"
        } else {
            "insufficient length"
        }
        Write-Verbose "Invalid SASL blob. Expected control characters 0x01 0x01 at end but found: $endChars"
        throw "SASL auth blob is incorrectly formatted. Missing control characters (0x01 0x01) at the end."
    }

    # Extract username: from after "user=" to before the control character preceding "auth="
    try {
        $startPos = $userIndex + $script:SASL_USER_PREFIX_LENGTH
        $length = $authIndex - 1 - $startPos  # -1 to exclude the control character

        if ($length -le 0) {
            throw "Invalid username length calculated: $length"
        }

        $userName = $DecodedBlob.Substring($startPos, $length)

        if ([string]::IsNullOrEmpty($userName)) {
            throw "Username is empty"
        }

        Write-Verbose "Extracted username: $userName"
    }
    catch {
        Write-Verbose "Failed to extract username from SASL blob"
        throw "AuthBlob does not contain a valid username"
    }

    # Extract token: from after "auth=Bearer " to before the final control characters
    try {
        $startPos = $bearerIndex + $script:SASL_BEARER_PREFIX_LENGTH
        $length = $DecodedBlob.Length - 2 - $startPos  # -2 to exclude the final ^A^A

        if ($length -le 0) {
            throw "Invalid token length calculated: $length"
        }

        $accessToken = $DecodedBlob.Substring($startPos, $length)

        if ([string]::IsNullOrEmpty($accessToken)) {
            throw "Access token is empty"
        }

        Write-Verbose "Extracted access token (length: $($accessToken.Length))"
    }
    catch {
        Write-Verbose "Failed to extract access token from SASL blob"
        throw "AuthBlob does not contain a valid access token"
    }

    return @{
        UserName = $userName
        AccessToken = $accessToken
    }
}

# OAuth token validation constants
$script:EXPECTED_AUDIENCES = @(
    "https://outlook.office365.com",
    "https://outlook.office.com",
    "https://outlook.office365.us"
)
$script:REQUIRED_DELEGATED_SCOPE = "SMTP.Send"
$script:REQUIRED_APPLICATION_ROLE = "SMTP.SendAsApp"

function Test-AccessTokenStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Result,
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    if ([string]::IsNullOrEmpty($AccessToken)) {
        Write-Verbose "Access token is null or empty. Skipping token verification."
        $Result.IsAuthTokenValid = $false
        return
    }

    try {
        # Parse and decode the JWT token
        $tokenParts = $AccessToken.Split(".")

        # Validate JWT structure (header.payload.signature)
        if ($tokenParts.Count -ne 3 -or
            [string]::IsNullOrEmpty($tokenParts[0]) -or
            [string]::IsNullOrEmpty($tokenParts[1])) {
            throw "Invalid JWT token structure. Expected 3 parts (header.payload.signature)"
        }

        # Decode and parse token claims
        try {
            # Validate header can be decoded
            DecodeBase64Value($tokenParts[0]) | Out-Null

            # Decode payload and convert from JSON
            $decodedPayload = DecodeBase64Value($tokenParts[1])
            $tokenClaims = ConvertFrom-Json $decodedPayload

            Write-Verbose "Successfully decoded JWT token claims"
        }
        catch {
            throw "Failed to decode JWT token or token payload is not valid JSON: $($_.Exception.Message)"
        }

        # Populate result with token information
        $Result.OAuthTokenAudience = $tokenClaims.aud
        $Result.OAuthTokenUpn = $tokenClaims.upn
        $Result.OAuthTokenScopes = $tokenClaims.scp
        $Result.OAuthTokenRoles = $tokenClaims.roles
        $Result.ApplicationId = $tokenClaims.appid
        $Result.AppDisplayName = $tokenClaims.app_displayname

        # Convert Unix timestamp to UTC DateTime
        if ($tokenClaims.exp) {
            try {
                $Result.OAuthTokenExpirationUtc = [System.DateTimeOffset]::FromUnixTimeSeconds($tokenClaims.exp).UtcDateTime
            }
            catch {
                Write-Verbose "Failed to parse token expiration time: $($tokenClaims.exp)"
                $Result.OAuthTokenExpirationUtc = $null
            }
        }

        # Validate token claims
        $isTokenValid = Test-TokenClaim -TokenClaims $tokenClaims -UserName $UserName

        $Result.IsAuthTokenValid = $isTokenValid
    }
    catch {
        Write-Verbose "OAuth token validation failed: $($_.Exception.Message)"
        throw "Token in auth blob is invalid: $($_.Exception.Message)"
    }
}

function Test-TokenClaim {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$TokenClaims,
        [Parameter(Mandatory = $true)]
        [string]$UserName
    )

    $validationResults = @()

    # Test audience claim
    if ($TokenClaims.aud -notin $script:EXPECTED_AUDIENCES) {
        Write-Verbose "Invalid audience claim. Expected one of: '$($script:EXPECTED_AUDIENCES -join "', '")' but found: '$($TokenClaims.aud)'"
        Write-Warning "Authentication token contains an invalid audience claim for SMTP Client Submission."
        $validationResults += $false
    }
    else {
        Write-Verbose "Token audience validation passed: $($TokenClaims.aud)"
        $validationResults += $true
    }

    # Test expiration
    if (-not $TokenClaims.exp) {
        Write-Verbose "Token does not contain expiration claim"
        Write-Warning "Authentication token does not contain expiration information."
        $validationResults += $false
    }
    else {
        try {
            $expirationTime = [System.DateTimeOffset]::FromUnixTimeSeconds($TokenClaims.exp).UtcDateTime
            $currentTime = (Get-Date).ToUniversalTime()

            if ($currentTime -gt $expirationTime) {
                Write-Verbose "Token has expired. Expiration: '$expirationTime', Current: '$currentTime'"
                Write-Warning "Authentication token has expired."
                $validationResults += $false
            }
            else {
                Write-Verbose "Token expiration validation passed. Expires: $expirationTime"
                $validationResults += $true
            }
        }
        catch {
            Write-Verbose "Failed to validate token expiration: $($_.Exception.Message)"
            Write-Warning "Unable to validate token expiration time."
            $validationResults += $false
        }
    }

    # Determine authentication type and test permissions
    $isApplicationAuth = [string]::IsNullOrEmpty($TokenClaims.upn)

    if ($isApplicationAuth) {
        Write-Verbose "Application authentication detected. UPN claim not found in token."
        Write-Output "Application authentication detected."

        # Only time empty roles are allowed is in RBAC enabled applications
        if (-not $script:RbacEnabled -and [string]::IsNullOrEmpty($TokenClaims.roles)) {
            Write-Verbose "Roles claim is null or empty"
            Write-Warning "Required permission for SMTP Client Submission not found in token."
            $validationResults += $false
        }
        else {
            # Check if roles is null before splitting
            if ([string]::IsNullOrEmpty($TokenClaims.roles)) {
                $roles = @()
            } else {
                $roles = $TokenClaims.roles.Split(' ')
            }

            # Check that no SMTP roles are present in RBAC enabled applications
            if ($script:RbacEnabled -and $script:REQUIRED_APPLICATION_ROLE -in $roles) {
                Write-Verbose "Unexpected SMTP roles found in RBAC enabled application."
                Write-Warning "RBAC enabled application should not have direct SMTP permissions assigned."
                $validationResults += $false
            }
            elseif ($script:REQUIRED_APPLICATION_ROLE -notin $roles) {
                Write-Verbose "Required role missing. Expected: '$script:REQUIRED_APPLICATION_ROLE', Found: '$($TokenClaims.roles)'"
                Write-Warning "Required permission for SMTP Client Submission not found in token."
                $validationResults += $false
            }
            else {
                Write-Verbose "Application permissions validation passed"
                $validationResults += $true
            }
        }
    }
    else {
        Write-Output "Delegated authentication detected"
        $isValid = $true

        # Validate UPN matches auth blob username
        if ($TokenClaims.upn -ne $UserName) {
            Write-Verbose "UPN mismatch. Token UPN: '$($TokenClaims.upn)', Auth blob username: '$UserName'"
            Write-Warning "UPN in authentication token and AuthBlob do not match."
            $isValid = $false
        }

        # Validate required scope
        if ([string]::IsNullOrEmpty($TokenClaims.scp)) {
            Write-Verbose "Scopes claim is null or empty"
            Write-Warning "Required permission for SMTP Client Submission not found in token."
            $isValid = $false
        }
        else {
            $scopes = $TokenClaims.scp.Split(' ')
            if ($script:REQUIRED_DELEGATED_SCOPE -notin $scopes) {
                Write-Verbose "Required scope missing. Expected: '$script:REQUIRED_DELEGATED_SCOPE', Found: '$($TokenClaims.scp)'"
                Write-Warning "Required permission for SMTP Client Submission not found in token."
                $isValid = $false
            }
            else {
                Write-Verbose "Delegated permissions validation passed"
            }
        }

        $validationResults += $isValid
    }

    # Return true only if all validations passed
    return ($validationResults -notcontains $false)
}
