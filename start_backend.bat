#!/bin/bash
# Kalıcı Backend Başlatıcı
# Bu betiği VS Code terminalde çalıştır: cmd /c "start cmd /k python -m uvicorn app.main:app --port 8001"

@echo off
title GenAI Backend
cls
echo ================================
echo GenAI Security Gateway - Backend
echo ================================
echo.

.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8001 --host 127.0.0.1

pause
