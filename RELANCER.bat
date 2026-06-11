@echo off
title PenToolbox - Relancement
echo.
echo  [..] Relancement PenToolbox...
docker start pentoolbox >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Container introuvable - relance INSTALLER.bat
    pause
    exit /b 1
)
timeout /t 4 /nobreak >nul
start "" "http://localhost:5000"
echo  [OK] PenToolbox demarre sur http://localhost:5000
echo  Login : admin / pentest2025
pause
