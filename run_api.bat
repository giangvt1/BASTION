@echo off
cd /d "%~dp0"
echo Starting BASTION Local API Server (using Python 3.14)...
C:\Python314\python.exe scripts/api_server.py
pause
