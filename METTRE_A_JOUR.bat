@echo off
setlocal enabledelayedexpansion
title PenToolbox - Mise a jour
color 0B

echo.
echo  =================================================
echo   PENTOOLBOX v4.0 - Mise a jour
echo  =================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Lance en tant qu'administrateur.
    pause & exit /b 1
)

REM -- Demarre Docker si besoin --
echo  [1/4] Verification Docker Engine...
docker info >nul 2>&1
if not errorlevel 1 goto :DOCKER_OK

echo  [..] Lancement Docker Desktop...
if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"

set WAIT=0
:WAIT_LOOP
timeout /t 5 /nobreak >nul
docker info >nul 2>&1
if not errorlevel 1 goto :DOCKER_OK
set /a WAIT+=1
echo  [..] Attente !WAIT!/20...
if !WAIT! lss 20 goto :WAIT_LOOP
echo  ERREUR : Docker ne repond pas.
pause & exit /b 1

:DOCKER_OK
echo  [OK] Docker Engine actif

REM -- Arret container --
echo.
echo  [2/4] Arret du container...
docker stop pentoolbox >nul 2>&1
docker rm pentoolbox >nul 2>&1
docker rmi pentoolbox:latest >nul 2>&1
echo  [OK] Ancien container supprime

REM -- Rebuild --
echo.
echo  [3/4] Reconstruction image...
echo  [..] Environ 2-3 minutes (cache utilise si possible)...
echo.
set BUILD_DIR=%~dp0
set BUILD_DIR=%BUILD_DIR:~0,-1%
docker build -t pentoolbox:latest "%BUILD_DIR%"
if errorlevel 1 (
    echo  ERREUR : Build echoue.
    pause & exit /b 1
)
echo  [OK] Image reconstruite

REM -- Relancement --
echo.
echo  [4/4] Relancement...
if not exist "%BUILD_DIR%\reports" mkdir "%BUILD_DIR%\reports"

REM Recupere tous les DNS via PowerShell
set DNS_FLAGS=
for /f "delims=" %%i in ('powershell -NoProfile -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | Where-Object {$_ -ne ''} | Get-Unique"') do (
    if not "%%i"=="" set DNS_FLAGS=!DNS_FLAGS! --dns %%i
)
REM Ajoute toujours 8.8.8.8 pour les domaines publics
if not "!DNS_FLAGS!"=="" (
    echo !DNS_FLAGS! | findstr "8.8.8.8" >nul 2>&1
    if errorlevel 1 set DNS_FLAGS=!DNS_FLAGS! --dns 8.8.8.8
) else (
    set DNS_FLAGS=--dns 8.8.8.8 --dns 1.1.1.1
)
echo  [*] DNS : %DNS_FLAGS%

docker run -d --name pentoolbox --restart unless-stopped -p 5000:5000 -v "%BUILD_DIR%\reports:/app/reports" --cap-add NET_ADMIN --cap-add NET_RAW %DNS_FLAGS% pentoolbox:latest >nul 2>&1
if errorlevel 1 (
    docker run -d --name pentoolbox --restart unless-stopped -p 5000:5000 -v "%BUILD_DIR%\reports:/app/reports" %DNS_FLAGS% pentoolbox:latest >nul 2>&1
)

timeout /t 5 /nobreak >nul
start "" "http://localhost:5000"

echo.
echo  =================================================
echo   [OK] MISE A JOUR TERMINEE
echo   Adresse : http://localhost:5000
echo   Login   : admin / pentest2025
echo  =================================================
echo.
pause
