@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set RUST_LOG=DEBUG

echo Working directory: %cd%
echo RUST_LOG = %RUST_LOG%

:: Check if anywhere.exe exists
if not exist "anywhere.exe" (
    echo.
    echo ERROR: anywhere.exe not found in %cd%
    echo.
    pause
    exit /b 1
)

:: Check administrator privileges via reg query (fails without admin)
reg query "HKU\S-1-5-19" >nul 2>&1
if !errorlevel! equ 0 (
    echo Running as administrator.
    goto :run
)

echo.
echo Not running as administrator.
echo Use transparent proxy mode? (requires admin)
echo   [Y] Yes, restart as admin
echo   [N] No, continue without admin
set "choice=N"
set /p choice=Select (y/N): 

if /i "!choice!"=="Y" (
    echo Restarting as admin...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\" ^& pause' -Verb RunAs"
    exit /b
)
echo Continuing without admin privileges.

:run
echo.
echo Starting anywhere.exe... (output -^> anywhere.log)
echo.

anywhere.exe > anywhere.log 2>&1
echo anywhere.exe exited with code !errorlevel!.

echo.
echo Press any key to close...
pause >nul
