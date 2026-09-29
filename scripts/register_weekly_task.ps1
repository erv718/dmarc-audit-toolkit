<#
.SYNOPSIS
  Register (or remove) the weekly scheduled run of the toolkit on Windows.

.DESCRIPTION
  Creates a Task Scheduler entry that runs  python src/collect.py  from the
  repo folder once a week. collect.py discovers your domains, pulls tenant
  data through the app registration, writes report.md and plan.md, keeps a
  dated history, and posts the Slack or Teams summary when a webhook is set
  in .env. The task runs as the current user, so the .env file and its
  permissions stay yours; nothing is stored in the task itself. By default it
  runs whether or not you are logged on (logon type S4U: no password is
  stored, and the task cannot reach network shares, which it does not need).
  -LogonType Interactive limits it to sessions where you are logged on.

  With an audit.toml next to collect.py the task needs no extra arguments:
  domains, retention and notification settings come from the file.

  Read-only toward the tenant, like everything else here. Windows PowerShell
  5.1 compatible. On macOS or Linux use cron or launchd with the same command
  (the README has the crontab line).

.EXAMPLE
  .\scripts\register_weekly_task.ps1                      # Monday 06:00, this repo
  .\scripts\register_weekly_task.ps1 -Day Tuesday -Time 07:30
  .\scripts\register_weekly_task.ps1 -LogonType Interactive
  .\scripts\register_weekly_task.ps1 -Unregister
#>
param(
    [string]$RepoPath = (Split-Path -Parent $PSScriptRoot),
    [string]$TaskName = "dmarc-audit-toolkit weekly",
    [ValidateSet("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")]
    [string]$Day = "Monday",
    [string]$Time = "06:00",
    [string]$Python = "python",
    [string]$ExtraArgs = "",
    [ValidateSet("S4U", "Interactive")]
    [string]$LogonType = "S4U",
    [switch]$Unregister
)

if ($Unregister) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        Write-Host "No task named '$TaskName' found."
        exit 0
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed task '$TaskName'."
    exit 0
}

$collect = Join-Path $RepoPath "src\collect.py"
if (-not (Test-Path $collect)) {
    Write-Host "collect.py not found at $collect - pass -RepoPath <repo folder>."
    exit 2
}
$pythonCmd = Get-Command $Python -ErrorAction SilentlyContinue
if ($null -eq $pythonCmd) {
    Write-Host "'$Python' is not on PATH - pass -Python <full path to python.exe>."
    exit 2
}

$arguments = "`"$collect`""
if ($ExtraArgs -ne "") { $arguments = "$arguments $ExtraArgs" }
$action = New-ScheduledTaskAction -Execute $pythonCmd.Source -Argument $arguments -WorkingDirectory $RepoPath
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType $LogonType -RunLevel Limited

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    Set-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    Write-Host "Updated task '$TaskName': every $Day at $Time ($LogonType), running $collect"
} else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Weekly DMARC audit: discover domains, pull tenant data read-only, write report.md and plan.md, post the summary." | Out-Null
    Write-Host "Registered task '$TaskName': every $Day at $Time ($LogonType), running $collect"
}
Write-Host "Test it now:  Start-ScheduledTask -TaskName '$TaskName'   then read audit-out\latest\report.md"
