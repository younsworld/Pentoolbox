@echo off
setlocal enabledelayedexpansion
title PenToolbox - Relancer
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX - Relancer tous les containers
echo  =================================================
echo.

cd /d "%~dp0deploy\docker"

echo  [1/2] Arreter containers...
docker compose down >nul 2>&1

echo  [2/2] Redemarrer containers...
docker compose up -d >nul 2>&1

if errorlevel 1 (
    echo  ERREUR : Impossible de relancer.
    pause
    exit /b 1
)

echo  [OK] 4 Containers redemarres

echo  [..] Attente initialisation (30 secondes)...
timeout /t 30 /nobreak >nul

start "" "https://localhost"

echo.
echo  =================================================
echo   [OK] PENTOOLBOX RELANCEE
echo   https://localhost
echo  =================================================
echo.
pause
