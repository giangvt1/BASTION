@echo off
cd /d "%~dp0"
echo Starting BASTION Local API Server...
python scripts/api_server.py
pause
