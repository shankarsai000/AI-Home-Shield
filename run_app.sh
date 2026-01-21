#!/bin/bash
# AI Home Shield - Linux/Mac Launcher

clear
echo "========================================"
echo "  AI Home Shield - Final Product v1.0"
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Please install Python 3.8+ using your package manager"
    exit 1
fi

echo "✓ Python found: $(python3 --version)"
echo ""

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not installed"
    echo "Please install pip using: sudo apt-get install python3-pip"
    exit 1
fi

echo "Checking dependencies..."

# Check required packages
if ! python3 -c "import streamlit; import pandas; import numpy" 2>/dev/null; then
    echo "Installing missing packages..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

echo "✓ All dependencies satisfied"
echo ""
echo "Starting AI Home Shield application..."
echo "The app will open in your default browser at http://localhost:8501"
echo ""

# Run the Streamlit app
python3 -m streamlit run app.py
