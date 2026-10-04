@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Script dir
cd /d "%~dp0"

:: Execute Powershell (.ps1) files alphabetically (non-blocking)
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    Start "" powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "%%A"
)

