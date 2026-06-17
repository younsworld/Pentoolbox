@echo off
title PenToolbox - Arret
color 0C

echo.
echo  =================================================
echo   PENTOOLBOX v4.0 - Arret
echo  =================================================
echo.

REM -- Verifie Docker --
docker --version >nul 2>&1
if errorlevel 1 (
    echo  [..] Docker non detecte - rien a arreter
    goto :END
)

REM -- Arret container --
echo  [1/2] Arret du container PenToolbox...
docker ps --filter "name=pentoolbox" --format "{{.Names}}" | findstr "pentoolbox" >nul 2>&1
if errorlevel 1 (
    echo  [OK] PenToolbox deja arrete
    goto :STOP_ENGINE
)

docker stop pentoolbox >nul 2>&1
echo  [OK] Container arrete

:STOP_ENGINE
REM -- Proposer d'arreter Docker Desktop aussi --
echo.
echo  [2/2] Arret Docker Desktop...
choice /C ON /M "Arreter aussi Docker Desktop ? O=Oui N=Non"
if errorlevel 2 goto :END

taskkill /f /im "Docker Desktop.exe" >nul 2>&1
taskkill /f /im "dockerd.exe" >nul 2>&1
echo  [OK] Docker Desktop arrete

:END
echo.
echo  =================================================
echo   [OK] PENTOOLBOX ARRETE
echo.
echo   LANCER.bat = relancer l'application
echo  =================================================
echo.
pause
