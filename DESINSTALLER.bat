@echo off
setlocal enabledelayedexpansion
title PenToolbox - Desinstaller
color 0C

echo.
echo  =================================================
echo   PENTOOLBOX - Desinstallation
echo  =================================================
echo.

echo  ATTENTION : Cette action supprimera le container et l'image Docker.
choice /C ON /M "Etes-vous sur ? (O=Oui N=Non)"
if errorlevel 2 (
    echo  Annule.
    pause
    exit /b 0
)

echo.
echo  [1/3] Arreter container...
docker stop pentoolbox >nul 2>&1

echo  [2/3] Supprimer container...
docker rm pentoolbox >nul 2>&1

echo  [3/3] Supprimer image...
docker rmi pentoolbox:latest >nul 2>&1

echo.
echo  =================================================
echo   [OK] PenToolbox desinstallee
echo  =================================================
echo.
pause
