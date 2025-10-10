@echo off
REM Secure Authentication Backend - Startup Script (Windows)

echo 🔒 Starting Secure Authentication Backend...
echo ==============================================

cd /d "%~dp0"

set PYTHON=C:\path\to\venv\Scripts\python.exe

if not exist "%PYTHON%" (
    echo ❌ Error: Python virtual environment not found
    echo Please update the PYTHON path in this script
    exit /b 1
)

if not exist ".env" (
    echo ⚠️  Warning: .env file not found, copying from .env.example
    copy .env.example .env
)

echo 📦 Checking dependencies...
%PYTHON% -c "import flask" 2>nul || (
    echo ❌ Dependencies not installed. Installing...
    %PYTHON% -m pip install -r requirements.txt
)

set PYTHONPATH=%cd%;%PYTHONPATH%

echo.
echo ✅ Starting Flask server on port 5001...
echo 📍 Health Check: http://localhost:5001/api/health
echo 📍 API Docs: See README.md for endpoint documentation
echo.
echo Press CTRL+C to stop the server
echo ==============================================
echo.

%PYTHON% app.py
