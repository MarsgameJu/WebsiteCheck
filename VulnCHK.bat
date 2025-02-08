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

if exist path\to\file\.venv\Scripts\activate (
    echo Activating virtual environment...
    call path\to\File\.venv\Scripts\activate
)

python path\to\File\Main.py

echo ==================================================
echo Scan completed.
pause
