function CheckVersionAndWarn() {
    [version]$installedVersion = (Get-Module -Name SmtpClientDiag).Version
    [version]$latestVersion;

    Write-Output "SMTP Client Diagnostic Version: $($installedVersion)"
    try {
        # Not using proxy
        $result = Invoke-WebRequest -Uri "https://github.com/richfaj/SmtpClientDiag/releases/latest/download/version.txt" -TimeoutSec 10 -UseBasicParsing
        $content = [System.Text.Encoding]::UTF8.GetString($result.Content)
        $latestVersion = [version]$content
    }
    catch {
        Write-Warning "Unable to check for updates. Please check your internet connection and try again."
    }

    if ($null -ne $latestVersion -and $installedVersion -lt $latestVersion) {
        Write-Warning "A newer version of SmtpClientDiag is available. Please update to the latest version using Update-Module cmdlet and restart the shell."
    }
}

function DecodeBase64Value {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [switch]$AllowUrlSafeEncoding
    )

    # Handle null or empty input
    if ([string]::IsNullOrEmpty($Value)) {
        Write-Verbose "Input value is null or empty, returning null"
        return $null
    }

    try {
        # Normalize the input
        $normalizedValue = Get-NormalizedBase64String -InputString $Value -AllowUrlSafe:$AllowUrlSafeEncoding

        # Add padding if needed
        $paddedValue = Add-Base64Padding -Base64String $normalizedValue

        # Decode the Base64 string
        Write-Verbose "Decoding Base64 string of length: $($paddedValue.Length)"
        $decodedBytes = [System.Convert]::FromBase64String($paddedValue)
        $decodedText = [System.Text.Encoding]::UTF8.GetString($decodedBytes)

        Write-Verbose "Successfully decoded Base64 string to UTF-8 text (length: $($decodedText.Length))"
        return $decodedText
    }
    catch [System.FormatException] {
        $errorMsg = "Invalid Base64 format. The input contains invalid characters or is malformed."
        Write-Verbose "Base64 decode failed: $errorMsg. Input: '$Value'"
        throw [System.ArgumentException]::new($errorMsg, "Value", $_.Exception)
    }
    catch [System.ArgumentException] {
        $errorMsg = "Invalid Base64 string length or format."
        Write-Verbose "Base64 decode failed: $errorMsg. Input: '$Value'"
        throw [System.ArgumentException]::new($errorMsg, "Value", $_.Exception)
    }
    catch {
        $errorMsg = "Failed to decode Base64 string: $($_.Exception.Message)"
        Write-Verbose "Unexpected error during Base64 decode: $errorMsg. Input: '$Value'"
        throw [System.InvalidOperationException]::new($errorMsg, $_.Exception)
    }
}

function Get-NormalizedBase64String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputString,

        [Parameter(Mandatory = $false)]
        [switch]$AllowUrlSafe
    )

    $result = $InputString.Trim()

    # Convert URL-safe Base64 to standard Base64 if requested
    if ($AllowUrlSafe) {
        $result = $result.Replace('-', '+').Replace('_', '/')
        Write-Verbose "Converted URL-safe Base64 characters to standard format"
    }

    # Validate Base64 character set
    if ($result -notmatch '^[A-Za-z0-9+/]*={0,2}$') {
        throw [System.FormatException]::new("Input contains invalid Base64 characters")
    }

    return $result
}

function Add-Base64Padding {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Base64String
    )

    $paddingNeeded = $Base64String.Length % 4

    switch ($paddingNeeded) {
        0 {
            Write-Verbose "No padding needed for Base64 string"
            return $Base64String
        }
        1 {
            # Invalid: Base64 length cannot have remainder of 1 when divided by 4
            throw [System.ArgumentException]::new("Invalid Base64 string length. Length cannot have a remainder of 1.")
        }
        2 {
            Write-Verbose "Adding 2 padding characters to Base64 string"
            return $Base64String + "=="
        }
        3 {
            Write-Verbose "Adding 1 padding character to Base64 string"
            return $Base64String + "="
        }
        default {
            throw [System.InvalidOperationException]::new("Unexpected padding calculation result: $paddingNeeded")
        }
    }
}

function GetCharHexValue([char] $char) {
    return ('{0:x}' -f [int]$char).ToUpper()
}
function Get-SmtpAccessToken() {
    param(
        [string]$ClientId,
        [string]$TenantId,
        [string]$UserName,
        [SecureString]$ClientSecret,
        [string]$AccessToken,
        [string]$VerbosePref)

    $VerbosePreference = $VerbosePref

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
            $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -ClientSecret $ClientSecret -Scope 'https://outlook.office.com/.default'
        }
        else {
            Write-Verbose "Using interactive login to obtain access token."
            $token = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Interactive -Scope 'https://outlook.office.com/Smtp.Send' -LoginHint $UserName
        }
        if ([System.String]::IsNullOrEmpty($token.AccessToken)) {
            throw "No token was available in the token request result."
        }

        return $token.AccessToken
    }
}
function RetrieveCertificateFromCertStore($thumbprint) {
    $cert = Get-ChildItem -Path "cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $thumbprint }

    if ($null -eq $cert -or ($cert | Measure-Object).Count -eq 0) {
        throw "No certificates found with thumbprint '$thumbprint' in LocalMachine certificate store."
    }

    # There should only be one certificate
    if (($cert | Measure-Object).Count -gt 1) {
        throw "More than one certificate found with thumbprint '$thumbprint'."
    }

    # Do we have access to the private key?
    if (-not $cert.HasPrivateKey) {
        throw "The certificate with thumbprint '$thumbprint' does not have a private key."
    }

    Write-Verbose "Found certificate with thumbprint '$thumbprint' in LocalMachine certificate store."
    return $cert
}

function Get-TlsVersion([string]$TlsVersion) {
    $enabledSslProtocols = $null

    if ($TlsVersion -eq "tls") {
        $enabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls
    }
    elseif ($TlsVersion -eq "tls11") {
        $enabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls11
    }
    elseif ($TlsVersion -eq "tls12") {
        $enabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
    }
    elseif ($TlsVersion -eq "tls13") {
        $enabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls13
    }

    return $enabledSslProtocols
}

function Invoke-DotNetDnsResolver {
    [CmdletBinding()]
    [OutputType([System.Object[]], [System.Net.IPAddress[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName
    )

    try {
        Write-Verbose "Resolving '$HostName' using internal .NET DNS resolver"

        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)

        if ($addresses.Count -gt 0) {
            Write-Verbose "Successfully resolved $($addresses.Count) address(es) for '$HostName'"
            return $addresses
        }
        else {
            Write-Verbose "DNS resolution returned no addresses for '$HostName'"
            return @()
        }
    }
    catch {
        Write-Verbose "DNS resolution failed for '$HostName': $($_.Exception.Message)"
        return @()
    }
}