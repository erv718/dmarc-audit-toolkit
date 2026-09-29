<#
.SYNOPSIS
Shared Exchange Online connection helper for the read-only auditors here.

.DESCRIPTION
Dot-sourced by audit_rules.ps1, audit_bypasses.ps1 and audit_groups.ps1;
not meant to be run alone. Connection order:

  1. an already-open Exchange Online session is used as-is
  2. app-only through the app registration: EXO_ORGANIZATION plus either
     EXO_CERT_THUMBPRINT (Windows certificate store) or EXO_CERT_FILE (a .pfx
     for macOS/Linux, with EXO_CERT_PASSWORD if it has one), from .env or the
     process environment, with the app id from EXO_APP_ID falling back to
     AZURE_CLIENT_ID (same registration the Python data plane uses; setup:
     docs/app-registration.md). The .pfx is tried first when both are set.
  3. interactive browser sign-in, offered only when someone is at the
     keyboard - nothing here ever hardcodes an account

Read-only either way: the auditors only ever run Get-* cmdlets.
#>

function Read-ToolkitEnv {
    # KEY=VALUE lines from <repo root>/.env, comments and blanks skipped.
    $values = @{}
    $envFile = Join-Path (Split-Path $PSScriptRoot -Parent) '.env'
    if (Test-Path $envFile) {
        foreach ($line in Get-Content $envFile) {
            $line = $line.Trim()
            if ($line -eq '' -or $line.StartsWith('#') -or $line -notmatch '=') { continue }
            $k, $v = $line -split '=', 2
            $values[$k.Trim()] = $v.Trim().Trim('"').Trim("'")
        }
    }
    return $values
}

function Get-ToolkitEnvValue {
    # Process environment wins over the file, same as the Python tools.
    param($Map, [string]$Name)
    $proc = [Environment]::GetEnvironmentVariable($Name)
    if ($proc) { return $proc }
    if ($Map.ContainsKey($Name)) { return $Map[$Name] }
    return ''
}

function Write-ToolkitAppOnlyHint {
    # what an app-only connect needs, printed after either certificate path fails
    Write-Host "Needs Exchange.ManageAsApp (Application) on the registration, a view-only role"
    Write-Host "(Global Reader is enough), and the certificate uploaded under Certificates & secrets."
    Write-Host "See docs/app-registration.md."
}

function Connect-ToolkitExo {
    param([switch]$Quiet)

    if (Get-ConnectionInformation -ErrorAction SilentlyContinue) { return $true }
    if (Get-Command Get-TransportRule -ErrorAction SilentlyContinue) { return $true }

    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "The ExchangeOnlineManagement module is missing:"
        Write-Host "  Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        return $false
    }
    Import-Module ExchangeOnlineManagement

    $map = Read-ToolkitEnv
    $appId = Get-ToolkitEnvValue $map 'EXO_APP_ID'
    if (-not $appId) { $appId = Get-ToolkitEnvValue $map 'AZURE_CLIENT_ID' }
    $thumb = Get-ToolkitEnvValue $map 'EXO_CERT_THUMBPRINT'
    $org = Get-ToolkitEnvValue $map 'EXO_ORGANIZATION'

    $certFile = Get-ToolkitEnvValue $map 'EXO_CERT_FILE'
    if ($certFile -and -not [System.IO.Path]::IsPathRooted($certFile)) {
        $certFile = Join-Path (Split-Path $PSScriptRoot -Parent) $certFile
    }
    $certPass = Get-ToolkitEnvValue $map 'EXO_CERT_PASSWORD'

    if ($appId -and $org -and $certFile) {
        if (Test-Path $certFile) {
            try {
                $params = @{ AppId = $appId; Organization = $org; ShowBanner = $false
                             CertificateFilePath = $certFile; ErrorAction = 'Stop' }
                if ($certPass) {
                    $params.CertificatePassword = (ConvertTo-SecureString $certPass -AsPlainText -Force)
                }
                Connect-ExchangeOnline @params
                return $true
            }
            catch {
                Write-Host "App-only Exchange Online connect with EXO_CERT_FILE failed: $($_.Exception.Message)"
                Write-ToolkitAppOnlyHint
            }
        }
        else {
            Write-Host "EXO_CERT_FILE points at $certFile, which is not there."
        }
    }

    if ($appId -and $thumb -and $org) {
        try {
            Connect-ExchangeOnline -AppId $appId -CertificateThumbprint $thumb `
                -Organization $org -ShowBanner:$false -ErrorAction Stop
            return $true
        }
        catch {
            Write-Host "App-only Exchange Online connect with EXO_CERT_THUMBPRINT failed: $($_.Exception.Message)"
            Write-ToolkitAppOnlyHint
        }
    }
    elseif (-not $certFile) {
        Write-Host "No EXO_CERT_THUMBPRINT / EXO_CERT_FILE / EXO_ORGANIZATION in .env - app-only not configured."
    }

    $answer = 'n'
    if (-not $Quiet) { $answer = Read-Host "Connect interactively in the browser instead? [y/N]" }
    if ($answer -match '^(?i)y(es)?$') {
        try {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        catch {
            Write-Host "Interactive connect failed: $($_.Exception.Message)"
            return $false
        }
        return [bool](Get-Command Get-TransportRule -ErrorAction SilentlyContinue)
    }
    Write-Host "Not connected. For app-only, set EXO_ORGANIZATION plus EXO_CERT_THUMBPRINT (Windows)"
    Write-Host "or EXO_CERT_FILE (macOS/Linux) in .env - see docs/app-registration.md - or run"
    Write-Host "Connect-ExchangeOnline yourself and re-run this script."
    return $false
}
