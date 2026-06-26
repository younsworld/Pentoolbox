@echo off
setlocal enabledelayedexpansion
title PenToolbox - Lancement (4 containers)
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX - Lancement
echo   4 Containers: PenToolbox + OpenVAS + Metasploit + Nginx
echo  =================================================
echo.

REM -- Droits admin --
net session >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Lance ce fichier en tant qu'administrateur.
    echo  Clic droit sur LANCER.bat puis Executer en tant qu'administrateur
    pause
    exit /b 1
)

REM -- Etape 1 : Docker installe ? --
echo  [1/3] Verification Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Docker non installe.
    echo  Lance INSTALLER.bat d'abord.
    pause
    exit /b 1
)
echo  [OK] Docker detecte

REM -- Etape 2 : Demarrage Docker Engine --
echo.
echo  [2/3] Demarrage Docker Engine...

docker info >nul 2>&1
if not errorlevel 1 goto :ENGINE_OK

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
if not errorlevel 1 goto :ENGINE_OK
set /a WAIT+=1
echo  [..] Attente !WAIT!/20...
if !WAIT! lss 20 goto :WAIT_LOOP

echo  ERREUR : Docker Engine ne repond pas.
pause
exit /b 1

:ENGINE_OK
echo  [OK] Docker Engine actif

REM -- Etape 3 : Demarrage containers --
echo.
echo  [3/3] Lancement containers...

cd /d "%~dp0deploy\docker"
docker compose up -d >nul 2>&1

if errorlevel 1 (
    echo  ERREUR : docker compose up echoue.
    pause
    exit /b 1
)

echo  [OK] 4 Containers lances:
echo       - pentoolbox
echo       - openvas
echo       - metasploit
echo       - nginx

echo  [..] Attente initialisation (30 secondes)...
timeout /t 30 /nobreak >nul

start "" "https://localhost"

echo.
echo  =================================================
echo   [OK] PENTOOLBOX EST PRET
echo.
echo   Adresse  : https://localhost
echo   Cert     : Auto-signe (ignorer l'avertissement)
echo.
echo   OpenVAS GUI : https://localhost:9392
echo.
echo   ARRETER.bat = stopper tous les containers
echo  =================================================
echo.
pause
