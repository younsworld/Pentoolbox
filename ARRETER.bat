@echo off
setlocal enabledelayedexpansion
title PenToolbox - Arreter
color 0C

echo.
echo  =================================================
echo   PENTOOLBOX - Arreter tous les services
echo  =================================================
echo.

REM -- Droits admin --
net session >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Lance ce fichier en tant qu'administrateur.
    pause
    exit /b 1
)

REM ================================================================
REM  Arreter docker-compose (4 containers)
REM ================================================================
echo  [1/3] Arreter docker-compose...
cd /d "%~dp0deploy\docker" 2>nul
if not errorlevel 1 (
    docker compose down >nul 2>&1
    if not errorlevel 1 (
        echo  [OK] docker-compose down
        goto :CLEANUP
    )
)

REM ================================================================
REM  Fallback: arreter les containers individuellement
REM ================================================================
:CLEANUP
echo  [2/3] Arreter les containers individuellement...

for %%C in (pentoolbox openvas metasploit nginx) do (
    docker stop %%C >nul 2>&1
    if not errorlevel 1 echo  [OK] %%C arrete
    docker rm %%C >nul 2>&1
    if not errorlevel 1 echo  [OK] %%C supprime
)

REM ================================================================
REM  Verifier que tout est arrete
REM ================================================================
echo.
echo  [3/3] Verification...
docker ps -a | findstr "pentoolbox openvas metasploit nginx" >nul 2>&1
if errorlevel 1 (
    echo  [OK] Tous les containers sont arretes
) else (
    echo  [!!] Certains containers sont encore actifs
    echo  Essaie: docker ps -a
    echo  Puis: docker stop [CONTAINER_ID]
)

echo.
echo  =================================================
echo   [OK] PENTOOLBOX ARRETEE
echo.
echo   Pour redemarrer: LANCER.bat
echo  =================================================
echo.
pause
