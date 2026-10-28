@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /O2 /W3 /Tc "%~dp0lab_detect.c" /Fe:"%~dp0lab_detect.exe" /link /SUBSYSTEM:CONSOLE advapi32.lib
