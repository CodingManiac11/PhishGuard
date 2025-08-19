@echo off
echo Setting up PhishGuard MVP with MongoDB Atlas...

REM Change to the project directory
cd /d "C:\Users\adity\OneDrive\Desktop\cyber\phishguard-mvp"

REM Check if virtual environment exists
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Test MongoDB connection (optional)
echo.
echo Testing MongoDB connection...
python test_mongo_connection.py

REM Start the application with MongoDB support
echo.
echo Starting PhishGuard MVP with MongoDB Atlas...
echo.
echo Dashboard will be available at: http://localhost:8000/
echo API documentation at: http://localhost:8000/docs
echo Health check at: http://localhost:8000/health
echo.
echo Press Ctrl+C to stop the server
echo.

python -m uvicorn backend.main_mongo:app --reload --port 8000

pause
