@echo off
setlocal enabledelayedexpansion
title PenToolbox v4.0 - Installation
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX v4.0 - Installation automatique
echo   4 Containers: PenToolbox + OpenVAS + Metasploit + Nginx
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'https://desktop.docker.com/win/main/amd64/Docker%%20Desktop%%20Installer.exe' -OutFile '%TEMP%\DockerInstaller.exe' -UseBasicParsing" >nul 2>&1

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

if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
    start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
    goto :WAIT_ENGINE
)
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" (
    start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"
    goto :WAIT_ENGINE
)

echo  Lance Docker Desktop manuellement...
pause
goto :WAIT_ENGINE

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
echo  [4/6] Nettoyage (suppression anciens containers)...
cd /d "%~dp0deploy\docker"
docker compose down >nul 2>&1

REM ================================================================
REM  ETAPE 5 : Build & Lancement Docker Compose
REM ================================================================
echo.
echo  [5/6] Construction et lancement des 4 containers...
echo  [..] PenToolbox + OpenVAS + Metasploit + Nginx
echo  [..] Cela peut prendre 10-15 minutes...
echo.

cd /d "%~dp0deploy\docker"
docker compose up -d --build >nul 2>&1

if errorlevel 1 (
    echo  ERREUR : docker compose echoue.
    pause
    exit /b 1
)

echo  [OK] Containers lances

REM ================================================================
REM  ETAPE 6 : Attendre que nginx soit pret
REM ================================================================
echo.
echo  [6/6] Attente initialisation...
timeout /t 10 /nobreak >nul

echo.
echo  =================================================
echo   [OK] INSTALLATION REUSSIE
echo.
echo   4 Containers actifs:
echo   - pentoolbox (Flask)
echo   - openvas (GVM Scanner)
echo   - metasploit (RPC)
echo   - nginx (HTTPS Reverse Proxy)
echo.
echo   Adresse  : https://localhost
echo   Cert     : Auto-signe (ignorer avertissement)
echo.
echo   Lance LANCER.bat pour demarrer
echo  =================================================
echo.
pause
