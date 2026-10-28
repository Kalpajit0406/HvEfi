@echo off
setlocal
rem Helper script to register, start, stop, or remove the HvDrv Windows Kernel Driver service.
rem Must be run as Administrator.
rem
rem Usage:
rem   manage_driver.bat install [path_to_HvDrv.sys]
rem   manage_driver.bat start
rem   manage_driver.bat stop
rem   manage_driver.bat remove
rem   manage_driver.bat status

set "SERVICE_NAME=HvDrv"
set "DEFAULT_BIN=%~dp0HvDrv\HvDrv.sys"

if "%1"=="install" (
    set "BIN_PATH=%~2"
    if "%BIN_PATH%"=="" set "BIN_PATH=%DEFAULT_BIN%"
    echo [*] Creating kernel driver service %SERVICE_NAME% at "%BIN_PATH%"...
    sc create %SERVICE_NAME% type= kernel binPath= "%BIN_PATH%"
    exit /b %ERRORLEVEL%
)

if "%1"=="start" (
    echo [*] Starting service %SERVICE_NAME%...
    sc start %SERVICE_NAME%
    exit /b %ERRORLEVEL%
)

if "%1"=="stop" (
    echo [*] Stopping service %SERVICE_NAME%...
    sc stop %SERVICE_NAME%
    exit /b %ERRORLEVEL%
)

if "%1"=="remove" (
    echo [*] Removing service %SERVICE_NAME%...
    sc stop %SERVICE_NAME% >nul 2>&1
    sc delete %SERVICE_NAME%
    exit /b %ERRORLEVEL%
)

if "%1"=="status" (
    sc query %SERVICE_NAME%
    exit /b %ERRORLEVEL%
)

echo HvDrv Service Manager
echo Usage: %0 {install [binPath] ^| start ^| stop ^| remove ^| status}
exit /b 1
