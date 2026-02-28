@echo off
echo ================================================
echo STARTING RICO BACKEND
echo ================================================
echo.

REM Change to project root
cd /d "%~dp0"

REM Set environment variable
set DEMO_API_URL=http://localhost:8000
echo [1/4] Environment variable set: DEMO_API_URL=%DEMO_API_URL%
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+
    pause
    exit /b 1
)
echo [2/4] Python found
echo.

REM Activate virtual environment if it exists
if exist venv\Scripts\activate.bat (
    echo [3/4] Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo [3/4] No virtual environment found, using system Python
)
echo.

REM Install/check dependencies
echo [4/4] Checking dependencies...
pip install -q fastapi uvicorn python-multipart
echo.

echo ================================================
echo BACKEND STARTING ON http://localhost:10000
echo ================================================
echo.
echo API Documentation: http://localhost:10000/docs
echo Health Check:      http://localhost:10000/health
echo.
echo IMPORTANT: Keep this window open!
echo Press Ctrl+C to stop the backend
echo.
echo ================================================
echo.

REM Start the backend
python -m uvicorn rico.web.main:app --host 0.0.0.0 --port 10000 --reload
