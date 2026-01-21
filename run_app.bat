@echo off
REM AI Home Shield - Windows Batch Launcher
REM This script runs the AI Home Shield application

setlocal enabledelayedexpansion

cls
echo ========================================
echo   AI Home Shield - Final Product v1.0
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set "PYTHON_VERSION=%%i"
echo [OK] Python found: %PYTHON_VERSION%
echo.

REM Check if requirements are installed
echo Checking dependencies...
python -c "import streamlit; import pandas; import numpy" >nul 2>&1
if errorlevel 1 (
    echo Installing missing packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [OK] All dependencies satisfied
echo.
echo Starting AI Home Shield application...
echo The app will open in your default browser at http://localhost:8501
echo.

REM Run the Streamlit app
streamlit run app.py
