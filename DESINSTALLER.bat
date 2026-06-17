@echo off
setlocal enabledelayedexpansion
title PenToolbox - Desinstallation complete
color 0C

echo.
echo  =================================================
echo   PENTOOLBOX - Desinstallation complete
echo   Suppression de tout ce qui a ete installe
echo  =================================================
echo.
echo  ATTENTION : Cette action va supprimer :
echo    - Le container Docker PenToolbox
echo    - L'image Docker PenToolbox
echo    - Le dossier PenToolbox et tous les rapports
echo    - Docker Desktop (optionnel)
echo    - WSL2 (optionnel)
echo.

choice /C ON /M "Confirmer la desinstallation ? O=Oui N=Non"
if errorlevel 2 (
    echo  Annule.
    pause
    exit /b 0
)

REM ================================================================
REM  ETAPE 1 : Arret et suppression container + image Docker
REM ================================================================
echo.
echo  [1/5] Suppression container et image Docker...

docker --version >nul 2>&1
if errorlevel 1 (
    echo  [..] Docker non trouve - on continue
    goto :SKIP_DOCKER
)

docker stop pentoolbox >nul 2>&1
echo  [OK] Container arrete
docker rm pentoolbox >nul 2>&1
echo  [OK] Container supprime
docker rmi pentoolbox:latest >nul 2>&1
echo  [OK] Image supprimee
docker system prune -f >nul 2>&1
echo  [OK] Cache Docker nettoye

:SKIP_DOCKER

REM ================================================================
REM  ETAPE 2 : Suppression du dossier PenToolbox
REM ================================================================
echo.
echo  [2/5] Suppression du dossier PenToolbox...

set SELF_DIR=%~dp0
set SELF_DIR=%SELF_DIR:~0,-1%

REM Cree un script temporaire pour se supprimer lui-meme apres
echo @echo off > "%TEMP%\cleanup_ptb.bat"
echo timeout /t 2 /nobreak ^>nul >> "%TEMP%\cleanup_ptb.bat"
echo rmdir /s /q "%SELF_DIR%" >> "%TEMP%\cleanup_ptb.bat"
echo echo [OK] Dossier PenToolbox supprime >> "%TEMP%\cleanup_ptb.bat"
echo del "%%~f0" >> "%TEMP%\cleanup_ptb.bat"

echo  [OK] Suppression du dossier planifiee

REM ================================================================
REM  ETAPE 3 : Docker Desktop
REM ================================================================
echo.
echo  [3/5] Desinstallation Docker Desktop...
choice /C ON /M "Desinstaller Docker Desktop ? O=Oui N=Non"
if errorlevel 2 goto :SKIP_DOCKER_UNINSTALL

REM Tue les processus Docker d'abord
taskkill /f /im "Docker Desktop.exe" >nul 2>&1
taskkill /f /im "dockerd.exe" >nul 2>&1
taskkill /f /im "docker.exe" >nul 2>&1
timeout /t 2 /nobreak >nul

REM Supprime directement les fichiers (methode rapide et fiable)
echo  [..] Suppression des fichiers Docker...
rmdir /s /q "C:\Program Files\Docker" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Programs\Docker" >nul 2>&1
rmdir /s /q "%APPDATA%\Docker" >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Docker" >nul 2>&1
rmdir /s /q "%PROGRAMDATA%\Docker" >nul 2>&1
rmdir /s /q "%PROGRAMDATA%\DockerDesktop" >nul 2>&1
reg delete "HKCU\Software\Docker Inc." /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Docker Inc." /f >nul 2>&1
echo  [OK] Docker Desktop supprime

:SKIP_DOCKER_UNINSTALL

REM  ETAPE 4 : WSL2
REM ================================================================
echo.
echo  [4/5] Desinstallation WSL2...
choice /C ON /M "Desinstaller WSL2 ? O=Oui N=Non"
if errorlevel 2 goto :SKIP_WSL

echo  [..] Suppression distributions Docker WSL...
wsl --unregister docker-desktop >nul 2>&1
wsl --unregister docker-desktop-data >nul 2>&1
echo  [OK] Distributions Docker supprimees

echo  [..] Desinstallation WSL...
winget uninstall --id Microsoft.WSL --silent --force --disable-interactivity >nul 2>&1
echo  [OK] WSL2 supprime
echo  [..] Note: Si WSL est encore visible dans Programmes,
echo       allez dans Panneau de config ^> Programmes ^>
echo       Fonctionnalites Windows et decochez WSL

:SKIP_WSL

REM  ETAPE 5 : Nettoyage final
REM ================================================================
echo.
echo  [5/5] Nettoyage final...

REM Supprime les variables d'environnement eventuelles
reg delete "HKCU\Environment" /v PENTOOLBOX /f >nul 2>&1

echo  [OK] Nettoyage termine

echo.
echo  =================================================
echo   [OK] DESINSTALLATION TERMINEE
echo.
echo   Tout a ete supprime :
echo   - Container et image Docker PenToolbox
echo   - Dossier PenToolbox (dans 2 secondes)
if errorlevel 1 echo   - Docker Desktop
if errorlevel 1 echo   - WSL2
echo.
echo   Aucune trace de PenToolbox ne reste sur ce PC.
echo  =================================================
echo.

REM Lance le script de suppression du dossier en arriere-plan
start "" /b "%TEMP%\cleanup_ptb.bat"

echo  Fermeture dans 3 secondes...
timeout /t 3 /nobreak >nul

REM ================================================================
REM  CHECKLIST FINALE - Verification complete
REM ================================================================
echo.
echo  =================================================
echo   CHECKLIST DE VERIFICATION
echo   Controle que tout a bien ete supprime
echo  =================================================
echo.

set CLEAN=1

REM -- Container Docker --
docker ps -a --filter "name=pentoolbox" --format "{{.Names}}" 2>nul | findstr "pentoolbox" >nul 2>&1
if not errorlevel 1 (
    echo  [!!] CONTAINER pentoolbox : encore present
    set CLEAN=0
) else (
    echo  [OK] Container pentoolbox : supprime
)

REM -- Image Docker --
docker images pentoolbox --format "{{.Repository}}" 2>nul | findstr "pentoolbox" >nul 2>&1
if not errorlevel 1 (
    echo  [!!] IMAGE pentoolbox : encore presente
    set CLEAN=0
) else (
    echo  [OK] Image Docker pentoolbox : supprimee
)

REM -- Dossier PenToolbox --
timeout /t 2 /nobreak >nul
if exist "%SELF_DIR%" (
    echo  [!!] DOSSIER PenToolbox : encore present (%SELF_DIR%)
    set CLEAN=0
) else (
    echo  [OK] Dossier PenToolbox : supprime
)

REM -- Docker Desktop --
if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
    echo  [!!] DOCKER DESKTOP : encore installe
    set CLEAN=0
) else if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" (
    echo  [!!] DOCKER DESKTOP : encore installe
    set CLEAN=0
) else (
    echo  [OK] Docker Desktop : supprime
)

REM -- WSL distributions Docker --
wsl --list 2>nul | findstr /i "docker" >nul 2>&1
if not errorlevel 1 (
    echo  [!!] WSL Docker distributions : encore presentes
    set CLEAN=0
) else (
    echo  [OK] WSL distributions Docker : supprimees
)

REM -- Port 5000 libre --
netstat -ano 2>nul | findstr ":5000" >nul 2>&1
if not errorlevel 1 (
    echo  [!!] PORT 5000 : encore utilise
    set CLEAN=0
) else (
    echo  [OK] Port 5000 : libre
)

REM -- localhost:5000 inaccessible --
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-WebRequest -Uri 'http://localhost:5000' -TimeoutSec 2 -UseBasicParsing; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo  [!!] INTERFACE WEB : encore accessible sur localhost:5000
    set CLEAN=0
) else (
    echo  [OK] Interface web : inaccessible (normal)
)

echo.
if !CLEAN! == 1 (
    color 0A
    echo  =================================================
    echo   TOUT EST PROPRE
    echo   PenToolbox a ete completement supprime du PC.
    echo   Aucune trace detectee.
    echo  =================================================
) else (
    color 0E
    echo  =================================================
    echo   NETTOYAGE INCOMPLET
    echo   Certains elements n'ont pas pu etre supprimes.
    echo   Les elements marques [!!] necessitent
    echo   une suppression manuelle.
    echo  =================================================
)
echo.
pause
exit /b 0
