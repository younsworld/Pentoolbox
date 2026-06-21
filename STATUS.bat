@echo off
title PenToolbox - Status
color 0A

echo.
echo  =================================================
echo   PENTOOLBOX - Status des containers
echo  =================================================
echo.

docker ps --filter "label=com.docker.compose.project=pentoolbox" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo.
echo  =================================================
echo.
pause
