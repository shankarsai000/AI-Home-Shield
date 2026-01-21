@echo off
REM AI Home Shield - Setup Assistant
REM Automated setup and verification

setlocal enabledelayedexpansion

cls
color 0A
title AI Home Shield - Setup Assistant

echo.
echo ╔════════════════════════════════════════╗
echo ║  AI Home Shield - Setup Verification   ║
echo ║          Final Product v1.0             ║
echo ╚════════════════════════════════════════╝
echo.

REM Check Python installation
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [FAILED] Python is not installed or not in PATH
    echo.
    echo Please follow these steps:
    echo 1. Go to https://www.python.org/downloads/
    echo 2. Download Python 3.10 or later
    echo 3. Run the installer
    echo 4. IMPORTANT: Check "Add Python to PATH" during installation
    echo 5. Restart your computer
    echo.
    echo After installing Python, run this script again.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set "PYTHON_VERSION=%%i"
color 0A
echo [OK] %PYTHON_VERSION%
echo.

REM Install/upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1

REM Install dependencies
echo Installing required packages...
echo This may take a few minutes on first run...
echo.
pip install -r requirements.txt

if errorlevel 1 (
    color 0C
    echo [FAILED] Could not install dependencies
    pause
    exit /b 1
)

color 0A
echo.
echo ╔════════════════════════════════════════╗
echo ║         Setup Completed!                ║
echo ╚════════════════════════════════════════╝
echo.
echo You can now run the application using:
echo   - Double-click: run_app.bat
echo   - or right-click run_app.ps1 and select "Run with PowerShell"
echo.
pause
