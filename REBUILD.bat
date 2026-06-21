@echo off
title PenToolbox - Rebuild
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX - Rebuild Image (HTTPS fix)
echo  =================================================
echo.

echo  [1/3] Arreter container...
docker stop pentoolbox >nul 2>&1

echo  [2/3] Supprimer image...
docker rmi pentoolbox:latest >nul 2>&1

echo  [3/3] Rebuilder image...
cd /d "%~dp0"
docker build -t pentoolbox:latest -f deploy/docker/Dockerfile . >nul 2>&1

if errorlevel 1 (
    echo  ERREUR : Build image echoue.
    pause
    exit /b 1
)

echo  [OK] Image rebuilde avec HTTPS

echo.
echo  Relance LANCER.bat pour demarrer
echo.
pause
