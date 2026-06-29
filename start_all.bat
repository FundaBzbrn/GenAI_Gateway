@echo off
REM ============================================================================
REM GenAI Security Gateway - Complete Startup Script
REM ============================================================================
REM This script starts both the FastAPI backend and Streamlit frontend
REM ============================================================================

echo.
echo ========================================
echo  GenAI Security Gateway - Startup
echo ========================================
echo.

REM Activate virtual environment
echo [1/3] Virtual environment aktivasyon yapiliyor...
call .venv\Scripts\activate.bat
echo OK - Virtual environment aktif

echo.

REM Check if .env exists
if not exist ".env" (
    echo [2/3] HATA: .env dosyasi bulunamadi!
    echo        Lutfen .env.template kopyalayarak .env olusturun
    pause
    exit /b 1
)
echo [2/3] .env dosyasi kontrol edildi - OK

echo.

REM Start Backend in background
echo [3/3] Backend baslatiliyor (Port 8001)...
start "GenAI Backend" .venv\Scripts\python.exe -m uvicorn app.main:app --port 8001 --reload
timeout /t 3 /nobreak

echo.
echo ========================================
echo  Streamlit UI baslatiliyor...
echo ========================================
echo.
echo Tarayici otomatik acilacak: http://localhost:8501
echo.

REM Start Streamlit
.venv\Scripts\streamlit.exe run streamlit_app.py

pause
