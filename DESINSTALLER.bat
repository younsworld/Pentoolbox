@echo off
setlocal enabledelayedexpansion
title PenToolbox - Desinstaller
color 0C

echo.
echo  =================================================
echo   PENTOOLBOX - Desinstallation
echo  =================================================
echo.

REM -- Droits admin (requis pour desinstaller Docker Desktop) --
net session >nul 2>&1
if errorlevel 1 (
    echo  ERREUR : Lance ce fichier en tant qu'administrateur.
    echo  Clic droit sur DESINSTALLER.bat puis Executer en tant qu'administrateur
    pause
    exit /b 1
)

echo  ATTENTION : suppression des containers et images PenToolbox.
echo  La desinstallation de Docker Desktop et de WSL2 sera proposee ensuite.
choice /C ON /M "Continuer ? (O=Oui N=Non)"
if errorlevel 2 (
    echo  Annule.
    pause
    exit /b 0
)

REM ================================================================
REM  ETAPE 1 : Arret et suppression de la stack Docker PenToolbox
REM ================================================================
echo.
echo  [1/4] Suppression des containers/images PenToolbox...
if exist "%~dp0deploy\docker\docker-compose.yml" (
    pushd "%~dp0deploy\docker"
    docker compose down -v >nul 2>&1
    popd
)
REM -- Container/image herites de l'installeur mono-container (docker run) --
docker stop pentoolbox >nul 2>&1
docker rm pentoolbox >nul 2>&1
docker rmi pentoolbox:latest >nul 2>&1
echo  [OK] Containers/images PenToolbox supprimes

REM ================================================================
REM  ETAPE 2 : Nettoyage des marqueurs temporaires de l'installeur
REM ================================================================
echo.
echo  [2/4] Nettoyage des fichiers temporaires...
del "%TEMP%\pentoolbox_post_reboot.flag" >nul 2>&1
del "%TEMP%\DockerInstaller.exe" >nul 2>&1
del "%TEMP%\docker_install.log" >nul 2>&1
echo  [OK] Marqueurs nettoyes

REM ================================================================
REM  ETAPE 3 : Desinstallation de Docker Desktop (optionnel)
REM ================================================================
echo.
echo  [3/4] Desinstallation de Docker Desktop...
set "DOCKER_UNINSTALLER="
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop Installer.exe" set "DOCKER_UNINSTALLER=%ProgramFiles%\Docker\Docker\Docker Desktop Installer.exe"
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop Installer.exe" set "DOCKER_UNINSTALLER=%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop Installer.exe"

if not defined DOCKER_UNINSTALLER (
    echo  [OK] Docker Desktop non detecte - rien a desinstaller
    goto :WSL_PROMPT
)

choice /C ON /M "Desinstaller Docker Desktop ? (O=Oui N=Non)"
if errorlevel 2 (
    echo  [..] Docker Desktop conserve
    goto :WSL_PROMPT
)

echo  [..] Desinstallation de Docker Desktop ^(plusieurs minutes - ne ferme pas cette fenetre^)...
start /w "" "!DOCKER_UNINSTALLER!" uninstall
set UNINSTALL_RC=%errorlevel%

REM -- Verification : "Docker Desktop.exe" ne doit plus exister --
set "DOCKER_PRESENT=0"
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" set "DOCKER_PRESENT=1"
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" set "DOCKER_PRESENT=1"

if "!DOCKER_PRESENT!"=="1" (
    echo  ERREUR : Docker Desktop semble toujours present ^(code !UNINSTALL_RC!^).
    echo  Desinstalle-le manuellement via Parametres ^> Applications.
) else (
    echo  [OK] Docker Desktop desinstalle
)

:WSL_PROMPT
REM ================================================================
REM  ETAPE 4 : WSL2 (NON supprime par defaut)
REM ================================================================
echo.
echo  [4/4] WSL2...
echo  WSL2 peut etre utilise par d'autres applications - conservation recommandee.
choice /C ON /M "Supprimer WSL2 ? (deconseille) O=Oui N=Non"
if errorlevel 2 (
    echo  [OK] WSL2 conserve
    goto :DONE
)
echo  [..] Desactivation des fonctionnalites WSL...
dism /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux /norestart >nul 2>&1
dism /online /disable-feature /featurename:VirtualMachinePlatform /norestart >nul 2>&1
echo  [OK] WSL2 desactive (un redemarrage peut etre necessaire)

:DONE
echo.
echo  =================================================
echo   [OK] PenToolbox desinstallee
echo  =================================================
echo.
pause
