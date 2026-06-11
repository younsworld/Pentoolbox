@echo off
setlocal enabledelayedexpansion
title PenToolbox v4.0 - Installation
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX v4.0 - Installation automatique
echo   WSL2 + Docker + Nmap + dig + arp-scan inclus
echo  =================================================
echo.

REM -- Droits admin --
net session >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Lance ce fichier en tant qu'administrateur.
    echo  Clic droit sur INSTALLER.bat puis Executer en tant qu'administrateur
    pause
    exit /b 1
)

REM ================================================================
REM  ETAPE 1 : WSL2
REM ================================================================
echo  [1/6] Verification WSL2...
wsl --update >nul 2>&1
wsl --set-default-version 2 >nul 2>&1
echo  [OK] WSL2 configure

REM ================================================================
REM  ETAPE 2 : Docker installe ?
REM ================================================================
echo.
echo  [2/6] Verification Docker...
docker --version >nul 2>&1
if not errorlevel 1 goto :DOCKER_OK

echo  [..] Docker absent - telechargement (~600 MB)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'https://desktop.docker.com/win/main/amd64/Docker%%20Desktop%%20Installer.exe' -OutFile '%TEMP%\DockerInstaller.exe' -UseBasicParsing"

if not exist "%TEMP%\DockerInstaller.exe" (
    echo  ERREUR : Telechargement echoue.
    echo  Installe Docker manuellement : https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

echo  [..] Installation Docker Desktop...
"%TEMP%\DockerInstaller.exe" install --quiet --accept-license --backend=wsl-2
del "%TEMP%\DockerInstaller.exe" >nul 2>&1

echo.
echo  =================================================
echo   Docker installe - REDEMARRAGE NECESSAIRE
echo   Apres redemarrage, relance INSTALLER.bat
echo  =================================================
choice /C ON /M "Redemarrer maintenant ? O=Oui N=Non"
if errorlevel 2 (
    echo  Redemarre manuellement puis relance INSTALLER.bat
    pause
    exit /b 0
)
shutdown /r /t 5
exit /b 0

:DOCKER_OK
echo  [OK] Docker detecte

REM ================================================================
REM  ETAPE 3 : Demarrage Docker Engine
REM ================================================================
echo.
echo  [3/6] Demarrage Docker Engine...

docker info >nul 2>&1
if not errorlevel 1 goto :ENGINE_READY

echo  [..] Lancement Docker Desktop...

if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    goto :WAIT_ENGINE
)
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" (
    start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"
    goto :WAIT_ENGINE
)
if exist "%PROGRAMFILES%\Docker\Docker\Docker Desktop.exe" (
    start "" "%PROGRAMFILES%\Docker\Docker\Docker Desktop.exe"
    goto :WAIT_ENGINE
)

echo  [..] Recherche Docker Desktop...
for /r "C:\" %%f in ("Docker Desktop.exe") do (
    start "" "%%f"
    goto :WAIT_ENGINE
)

:WAIT_ENGINE
set WAIT=0
:WAIT_LOOP
timeout /t 5 /nobreak >nul
docker info >nul 2>&1
if not errorlevel 1 goto :ENGINE_READY
set /a WAIT+=1
echo  [..] Attente !WAIT!/20...
if !WAIT! lss 20 goto :WAIT_LOOP

echo  ERREUR : Docker Engine ne repond pas.
echo  Lance Docker Desktop manuellement et relance INSTALLER.bat
pause
exit /b 1

:ENGINE_READY
echo  [OK] Docker Engine actif

REM ================================================================
REM  ETAPE 4 : Nettoyage
REM ================================================================
echo.
echo  [4/6] Nettoyage...
docker stop pentoolbox >nul 2>&1
docker rm pentoolbox >nul 2>&1
echo  [OK] Pret

REM ================================================================
REM  ETAPE 5 : Build image
REM ================================================================
echo.
echo  [5/6] Construction image PenToolbox...
echo  [..] Premiere fois : 3-5 min  Fois suivantes : 10 sec
echo.

set BUILD_DIR=%~dp0
set BUILD_DIR=%BUILD_DIR:~0,-1%

docker build -t pentoolbox:latest "%BUILD_DIR%"
if errorlevel 1 (
    echo.
    echo  ERREUR : Build Docker echoue.
    pause
    exit /b 1
)
echo  [OK] Image construite

REM ================================================================
REM  ETAPE 6 : Lancement
REM ================================================================
echo.
echo  [6/6] Lancement PenToolbox...

if not exist "%BUILD_DIR%\reports" mkdir "%BUILD_DIR%\reports"

docker run -d --name pentoolbox --restart unless-stopped -p 5000:5000 -v "%BUILD_DIR%\reports:/app/reports" --cap-add NET_ADMIN --cap-add NET_RAW pentoolbox:latest
if errorlevel 1 (
    echo  [..] Tentative sans caps reseau...
    docker run -d --name pentoolbox --restart unless-stopped -p 5000:5000 -v "%BUILD_DIR%\reports:/app/reports" pentoolbox:latest
    if errorlevel 1 (
        echo  ERREUR : Lancement container echoue.
        pause
        exit /b 1
    )
)

echo  [..] Attente demarrage...
timeout /t 6 /nobreak >nul

start "" "http://localhost:5000"

echo.
echo  =================================================
echo   [OK] PENTOOLBOX EST PRET
echo.
echo   Adresse  : http://localhost:5000
echo   Login    : admin / pentest2025
echo.
echo   ARRETER.bat  = stopper l'application
echo   RELANCER.bat = relancer apres redemarrage PC
echo  =================================================
echo.
pause
