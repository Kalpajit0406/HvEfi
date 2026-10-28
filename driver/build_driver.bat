@echo off
setlocal

rem Build script for HvDrv Windows Kernel Driver
rem Requirements: Visual Studio 2022 (MSVC x64) + WDK10 at C:\Users\DELL\WDK10

set "VCTOOLS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231"
set "WDKROOT=C:\Users\DELL\WDK10"
set "SDKROOT=C:\Program Files (x86)\Windows Kits\10"
set "WDKVER=10.0.28000.0"

if not exist "%VCTOOLS%\bin\Hostx64\x64\cl.exe" (
    set "VCTOOLS_BIN=%VCTOOLS%\bin\Hostx86\x64"
) else (
    set "VCTOOLS_BIN=%VCTOOLS%\bin\Hostx64\x64"
)

set "CL_EXE=%VCTOOLS_BIN%\cl.exe"
set "ML64_EXE=%VCTOOLS_BIN%\ml64.exe"
set "LINK_EXE=%VCTOOLS_BIN%\link.exe"

set CFLAGS=/c /O2 /Oi /GS- /W4 /wd4201 /Zl /nologo /D_AMD64_ /DWIN64 /D_WIN64 /DWINNT=1 /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000B /DDBG=1
set LDFLAGS=/OUT:HvDrv.sys /DLL /MACHINE:X64 /NODEFAULTLIB /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /DYNAMICBASE /NXCOMPAT /INTEGRITYCHECK /nologo /PDBALTPATH:HvDrv.pdb

cd /d "%~dp0HvDrv"

echo [*] Assembling hv_asm.asm...
"%ML64_EXE%" /nologo /c /Cx /Fo hv_asm.obj hv_asm.asm
if errorlevel 1 (
    echo [-] Assembly failed!
    exit /b 1
)

echo [*] Compiling hv_driver.c...
"%CL_EXE%" %CFLAGS% "/I%WDKROOT%\Include\%WDKVER%\km" "/I%SDKROOT%\Include\%WDKVER%\shared" "/I%SDKROOT%\Include\%WDKVER%\ucrt" "/I%VCTOOLS%\include" hv_driver.c /Fo:hv_driver.obj
if errorlevel 1 (
    echo [-] Compilation failed!
    exit /b 1
)

echo [*] Linking HvDrv.sys...
"%LINK_EXE%" %LDFLAGS% hv_driver.obj hv_asm.obj ntoskrnl.lib hal.lib "/LIBPATH:%WDKROOT%\Lib\%WDKVER%\km\x64" "/LIBPATH:%VCTOOLS%\lib\x64"
if errorlevel 1 (
    echo [-] Linking failed!
    exit /b 1
)

echo [+] Successfully built: %~dp0HvDrv\HvDrv.sys
exit /b 0
