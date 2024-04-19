class Logger {
    hidden $LogLines = @()
    hidden [bool]$EnableVerbose = $false

    Logger([string]$pref) {
        if ($pref -eq "Continue") {
            $this.EnableVerbose = $true
        }
    }

    [void] LogMessage ([string]$message) {
        $this.LogMessage($message, "Information", "", $false, $false)
    }
    [void] LogMessage([string]$message, [string]$type, [bool]$logOnly = $false, [bool]$noTimestamp = $false) {
        $this.LogMessage($message, $type, "", $logOnly, $noTimestamp)
    }
    [void] LogMessage([string]$message, [string]$type = "Information", [string]$foregroundColor, [bool]$logOnly = $false, [bool]$noTimestamp = $false) {
        if ($this.EnableVerbose) {
            $VerbosePreference = "Continue"
        }
        if ($type -eq "Verbose" -and -not $this.EnableVerbose) {
            return
        }
        if ($type -eq "Warning") {
            Write-Warning -Message $message
            return
        }
        $line = $null

        if ($noTimestamp) {
            $line = $message
        }
        else {
            $line = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK") + " " + $message
        }

        if (-not $logOnly) {
            if ($type -eq "Verbose") {
                Write-Verbose $message
                $line = "VERBOSE: $message"
            }
            else {
                if (-not [string]::IsNullOrEmpty($ForegroundColor)) {
                    Write-Host $line -ForegroundColor $ForegroundColor
                }
                else {
                    Write-Host $line
                }
            }
        }

        $this.LogLines += $line
    }
    [void] LogError ([string]$message) {
        $this.LogError($message, $false)
    }
    [void] LogError ([string]$message, [bool]$logOnly) {
        $this.LogMessage($message, "Error", "Red", $logOnly, $true)
    }
    [void] WriteFile([string]$logPath) {
        [string]$fileName = "smtpdiag_" + (Get-Date).ToUniversalTime().ToString("MMddyyhhmmss") + ".log"
        [string]$joinedPath = $null

        # Check if custom log path provided
        if (-not [System.String]::IsNullOrEmpty($logPath)) {
            $joinedPath = Join-Path -Path $logPath -ChildPath $fileName
        }

        # Use working directory
        else {
            # Check path exist
            if ((Test-Path 'logs' -PathType Container) -eq $false) {
                New-Item -Path 'logs' -ItemType Directory -Force | Out-null
            }

            $joinedPath = Join-Path -Path (Get-Location).Path -ChildPath $fileName
        }

        $this.LogLines | Out-File -FilePath $joinedPath -Append -Force
        Write-Host -ForegroundColor Green "Saved log file to: $joinedPath"
    }
}

