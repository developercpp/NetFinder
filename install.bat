@echo off
title NetFinder - Installer
color 0A

echo.
echo  ---------------------------------------------
echo             NetFinder Installer
echo  ----------------------------------------------
echo.


python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version
echo.


pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not available!
    echo.
    echo Try running: python -m ensurepip --upgrade
    echo.
    pause
    exit /b 1
)

echo [OK] pip found:
pip --version
echo.


echo [*] Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
echo.


echo [*] Installing dependencies from requirements.txt...
echo.
pip install -r "%~dp0requirements.txt"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to install some dependencies!
    echo.
    pause
    exit /b 1
)

echo.
echo   Installation Complete!
echo.
echo  Next steps:
echo    1. Run start_chrome.bat to launch Chrome
echo    2. Run: python finder.py
echo.
pause

