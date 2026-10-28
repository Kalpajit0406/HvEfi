@echo off
setlocal
cd /d "%~dp0lab_detect_rs"
cargo build --release
if %ERRORLEVEL% equ 0 (
    copy /y target\release\lab_detect_rs.exe ..\lab_detect_rs.exe >nul
    echo [+] Successfully built client\lab_detect_rs.exe
)
