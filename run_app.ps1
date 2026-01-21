# AI Home Shield - Desktop Launcher
# This script runs the AI Home Shield application

$appDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $appDir

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AI Home Shield - Final Product v1.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from https://www.python.org" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✓ Python found: $(python --version)" -ForegroundColor Green
Write-Host ""

# Check if requirements are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow
$requirements = @("streamlit", "pandas", "numpy")
$missingPackages = @()

foreach ($package in $requirements) {
    $checkResult = python -c "import $package" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $missingPackages += $package
    }
}

if ($missingPackages.Count -gt 0) {
    Write-Host "Installing missing packages: $($missingPackages -join ', ')" -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host "✓ All dependencies satisfied" -ForegroundColor Green
Write-Host ""
Write-Host "Starting AI Home Shield application..." -ForegroundColor Cyan
Write-Host "The app will open in your default browser at http://localhost:8501" -ForegroundColor Cyan
Write-Host ""

# Run the Streamlit app
streamlit run app.py
