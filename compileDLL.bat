@ECHO OFF

rem cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:vcmigrate.exe /SUBSYSTEM:CONSOLE
cl.exe /nologo /W0 unloadsysmon.cpp /MT /link /DLL /OUT:unloadsysmon.dll
cl.exe /nologo /W0 findsysmon.cpp /MT /link /DLL /OUT:findsysmon.dll
cl.exe /nologo /W0 disableETW.cpp /MT /link /DLL /OUT:disableETW.dll
cl.exe /nologo /W0 lockETW.cpp /MT /link /DLL /OUT:lockETW.dll
del *.obj