# AI Home Shield - Final Product

## Quick Start

### Option 1: Windows Batch File (Easiest)
Double-click `run_app.bat` to launch the application.

### Option 2: PowerShell
Right-click `run_app.ps1` and select "Run with PowerShell".

### Option 3: Command Line
```bash
cd path\to\AI_Home_Shield
streamlit run app.py
```

## System Requirements

- **Python 3.8+** (Download from https://www.python.org)
- **Windows 10+** (for native device scanning features)
- **Administrator privileges** (for firewall and port blocking features)

## Features

- **Device Discovery**: Automatically detect devices on your network
- **Threat Detection**: Monitor and identify suspicious network activity
- **AI-Powered Response**: Autonomous threat response with multiple agent types
- **Honeypot Deception**: Deploy decoys to detect attackers
- **Firewall Management**: Block malicious IPs in real-time
- **Health Monitoring**: Track agent and system health status

## Dependencies

All required packages are listed in `requirements.txt` and will be installed automatically when you first run the application.

Main dependencies:
- **streamlit**: Web UI framework
- **pandas**: Data processing
- **numpy**: Numerical computing
- **scapy**: Network packet handling
- **psutil**: System information

## Troubleshooting

### Python Not Found
If you get "Python is not installed", make sure Python is added to your system PATH:
1. Download Python from https://www.python.org
2. During installation, check "Add Python to PATH"
3. Restart your computer

### Port Already in Use
If port 8501 is already in use, Streamlit will automatically use the next available port (8502, 8503, etc.).

### Permission Denied
Some features (firewall blocking) require administrator privileges. Run the launcher with Administrator rights.

## Project Structure

```
AI_Home_Shield/
├── app.py                 # Main Streamlit application
├── agents/               # AI agent modules
│   ├── discovery_agent.py
│   ├── risk_agent.py
│   ├── response_agent.py
│   └── ... (other agents)
├── utils/               # Utility functions
├── data/               # Sample data files
├── honeytokens/        # Honeypot decoy files
├── logs/               # Application logs
└── models/             # ML model files
```

## Support

For issues or questions, refer to:
- QUICK_START.md - Quick reference guide
- WINNING_GUIDE.md - Detailed feature guide
- FINAL_STATUS_REPORT.txt - Project status and features

---

**Version**: 1.0
**Last Updated**: January 2026
