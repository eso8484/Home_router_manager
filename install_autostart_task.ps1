param(
    [string]$TaskName = "MonitorsNetworkWSL",
    [string]$Distro = "Ubuntu-24.04",
    [string]$LinuxUser = "eso",
    [string]$ProjectPath = "/mnt/c/Users/enejo/Downloads/monitors_network"
)

$ErrorActionPreference = "Stop"

# Build WSL command that starts monitor only if not already running.
$wslArgs = "-d $Distro -u $LinuxUser -- bash -lc \"cd $ProjectPath && chmod +x run_monitor.sh && ./run_monitor.sh\""

$action = New-ScheduledTaskAction -Execute "wsl.exe" -Argument $wslArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 0)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Scheduled task '$TaskName' installed for user '$env:USERNAME'."
Write-Host "It will run at Windows logon and start the monitor in WSL."
Write-Host "You can test now with: schtasks /Run /TN $TaskName"
