@echo off
echo.
echo ===============================================
echo   🚀 PhishGuard MVP - MongoDB Atlas Edition
echo ===============================================
echo.

cd /d "%~dp0"
echo 📁 Working directory: %cd%
echo.

echo 🔧 Activating virtual environment...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment
    echo Please ensure .venv exists and contains Scripts\activate.bat
    pause
    exit /b 1
)

echo ✅ Virtual environment activated
echo.

echo 🚀 Starting PhishGuard server...
echo 🔗 Server will be available at: http://127.0.0.1:8000
echo 📊 Dashboard: http://127.0.0.1:8000
echo 📖 API Docs: http://127.0.0.1:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.

python start.py