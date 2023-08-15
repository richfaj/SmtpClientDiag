function CheckVersionAndWarn() {
    [version]$installedVersion = (Get-Module -Name SmtpClientDiag).Version
    [version]$latestVersion;

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

function DecodeBase64Value([string] $value) {
    if ([string]::IsNullOrEmpty($value)) {
        return $null
    }
    # Token is base64 encoded and must be a multiple of 4 characters in length. Add padding if needed.
    if ($value.Length % 4 -eq 2) {
        $value += "=="
    }
    elseif ($value.Length % 4 -eq 3) {
        $value += "="
    }
    elseif ($value.Length % 4 -ne 0) {
        Write-Verbose "Failed to decode base64 string: $value"
        throw "Invalid length for a base64 string."
    }

    $valueBytes = [System.Convert]::FromBase64String($value)
    return [System.Text.Encoding]::UTF8.GetString($valueBytes)
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
