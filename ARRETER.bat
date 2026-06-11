@echo off
title PenToolbox - Arret
echo.
echo  [..] Arret PenToolbox...
docker stop pentoolbox >nul 2>&1
echo  [OK] PenToolbox arrete.
pause
