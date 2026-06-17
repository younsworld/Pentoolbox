@echo off
setlocal enabledelayedexpansion
title PenToolbox - Relancement
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX v4.0 - Relancement
echo  =================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Lance en tant qu'administrateur.
    pause & exit /b 1
)

REM -- Verifie Docker --
echo  [1/3] Verification Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Docker non installe. Lance INSTALLER.bat d'abord.
    pause & exit /b 1
)
echo  [OK] Docker detecte

REM -- Demarre Docker Engine si besoin --
echo.
echo  [2/3] Demarrage Docker Engine...
docker info >nul 2>&1
if not errorlevel 1 goto :ENGINE_OK

echo  [..] Lancement Docker Desktop...
if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"

set WAIT=0
:WAIT_LOOP
timeout /t 5 /nobreak >nul
docker info >nul 2>&1
if not errorlevel 1 goto :ENGINE_OK
set /a WAIT+=1
echo  [..] Attente !WAIT!/20...
if !WAIT! lss 20 goto :WAIT_LOOP
echo  ERREUR : Docker ne repond pas.
pause & exit /b 1

:ENGINE_OK
echo  [OK] Docker Engine actif

REM -- Arret + Suppression + Recréation container --
echo.
echo  [3/3] Relancement PenToolbox...

docker stop pentoolbox >nul 2>&1
docker rm pentoolbox >nul 2>&1

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

set BUILD_DIR=%~dp0
set BUILD_DIR=%BUILD_DIR:~0,-1%
if not exist "%BUILD_DIR%\reports" mkdir "%BUILD_DIR%\reports"

docker run -d --name pentoolbox --restart unless-stopped -p 5000:5000 -v "%BUILD_DIR%\reports:/app/reports" --cap-add NET_ADMIN --cap-add NET_RAW %DNS_FLAGS% pentoolbox:latest >nul 2>&1
if errorlevel 1 (
    docker run -d --name pentoolbox --restart unless-stopped -p 5000:5000 -v "%BUILD_DIR%\reports:/app/reports" %DNS_FLAGS% pentoolbox:latest >nul 2>&1
)

echo  [..] Attente demarrage...
timeout /t 4 /nobreak >nul
start "" "http://localhost:5000"

echo.
echo  =================================================
echo   [OK] PENTOOLBOX LANCE
echo   Adresse : http://localhost:5000
echo   Login   : admin / pentest2025
echo  =================================================
echo.
pause
