@ECHO OFF

rem cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp original.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
cl.exe /nologo /Ox /MT /GS- /DNDEBUG /Tp original.cpp /link /OUT:stage1.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj
