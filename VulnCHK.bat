@echo off
title VulnCHK Scanner
echo Starting VulnCHK...
echo ==================================================

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python is not installed or not in PATH.
    pause
    exit /b
)

if exist .venv\Scripts\activate (
    echo Activating virtual environment...
    call .venv\Scripts\activate
)

python Main.py

echo ==================================================
echo Scan completed.
pause
