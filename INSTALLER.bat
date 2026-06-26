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

REM -- Detection de curl.exe (Win10 1803+) pour la barre de progression --
set "HAS_CURL="
where curl >nul 2>&1 && set "HAS_CURL=1"

REM ================================================================
REM  ETAPE 1 : WSL2
REM ================================================================
echo  [1/6] Verification WSL2...
REM -- Au retour de redemarrage (marqueur present), tout est deja configure --
if exist "%TEMP%\pentoolbox_post_reboot.flag" goto :WSL_DONE

REM -- Active les fonctionnalites Windows requises si elles sont absentes.   --
REM -- Cas classique apres un DESINSTALLER qui a desactive WSL2 / VMP : le    --
REM -- script tourne en admin, on les reactive nous-memes au lieu d echouer.  --
set "WSL_NEEDS_REBOOT="
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $a=(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State; $b=(Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State; if($a -ne 'Enabled' -or $b -ne 'Enabled'){exit 1}; exit 0"
if not errorlevel 1 goto :WSL_FEATURES_OK
echo  [..] Activation de WSL2 / VirtualMachinePlatform ^(admin^)...
dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart >nul 2>&1
dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart >nul 2>&1
set "WSL_NEEDS_REBOOT=1"
:WSL_FEATURES_OK
wsl --update >nul 2>&1
wsl --set-default-version 2 >nul 2>&1
if not defined WSL_NEEDS_REBOOT goto :WSL_DONE

echo. > "%TEMP%\pentoolbox_post_reboot.flag"
echo.
echo  =================================================
echo   [OK] Fonctionnalites Windows activees - REDEMARRAGE NECESSAIRE
echo   Apres le redemarrage, relance INSTALLER.bat
echo   (il reprendra automatiquement a l etape suivante)
echo  =================================================
choice /C ON /M "Redemarrer maintenant ? O=Oui N=Non"
if errorlevel 2 (
    echo  Redemarre manuellement puis relance INSTALLER.bat
    pause
    exit /b 0
)
shutdown /r /t 5
exit /b 0
:WSL_DONE
echo  [OK] WSL2 configure

REM ================================================================
REM  ETAPE 2 : Docker installe ?  (PATH -> disque -> registre)
REM ================================================================
echo.
echo  [2/6] Verification Docker...

REM -- Repare le PATH de session si docker.exe est sur le disque mais --
REM -- pas encore propage (etat classique apres install + redemarrage)  --
if exist "%ProgramFiles%\Docker\Docker\resources\bin\docker.exe" set "PATH=%ProgramFiles%\Docker\Docker\resources\bin;%PATH%"
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\resources\bin\docker.exe" set "PATH=%LOCALAPPDATA%\Programs\Docker\Docker\resources\bin;%PATH%"

REM -- a) docker.exe resolvable sur le PATH ? --
docker --version >nul 2>&1
if not errorlevel 1 goto :DOCKER_OK

REM -- b) installe sur le disque mais pas encore lance ? --
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" goto :DOCKER_OK
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" goto :DOCKER_OK

REM -- c) present dans le registre ? --
reg query "HKLM\SOFTWARE\Docker Inc.\Docker Desktop" >nul 2>&1
if not errorlevel 1 goto :DOCKER_OK

REM ================================================================
REM  Aucun signe d'installation : prerequis -> telechargement -> install
REM ================================================================
echo  [..] Docker absent - verification des prerequis Windows...

REM -- Pre-flight : echoue vite (avant de telecharger 600 MB) si un --
REM -- prerequis manque, avec une instruction de correction concrete. --
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $fail=0; $b=[int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber; if($b -lt 19041){Write-Host '  [X] Windows trop ancien (build '$b'). Requis: Windows 10 2004 (build 19041)+ ou Windows 11.'; $fail=1}else{Write-Host '  [OK] Version Windows (build '$b')'}; $vmp=(Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State; if($vmp -ne 'Enabled'){Write-Host '  [X] VirtualMachinePlatform desactive.'; Write-Host '      Corriger (admin): dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart'; $fail=1}else{Write-Host '  [OK] VirtualMachinePlatform'}; $wsl=(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State; if($wsl -ne 'Enabled'){Write-Host '  [X] Microsoft-Windows-Subsystem-Linux desactive.'; Write-Host '      Corriger (admin): dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart'; $fail=1}else{Write-Host '  [OK] Microsoft-Windows-Subsystem-Linux'}; $cs=Get-CimInstance Win32_ComputerSystem; $p=Get-CimInstance Win32_Processor ^| Select-Object -First 1; if($cs.HypervisorPresent -or $p.VirtualizationFirmwareEnabled){Write-Host '  [OK] Virtualisation materielle'}else{Write-Host '  [X] Virtualisation desactivee dans le BIOS/UEFI (activer Intel VT-x / AMD-V SVM).'; $fail=1}; exit $fail"
if errorlevel 1 (
    echo.
    echo  ERREUR : Prerequis Windows manquants ^(voir la liste ci-dessus^).
    echo  Corrige les points marques [X] puis relance INSTALLER.bat.
    pause
    exit /b 1
)
echo  [OK] Prerequis Windows valides

echo  [..] Telechargement de Docker Desktop ^(~600 MB^)...
if defined HAS_CURL (
    curl.exe -L --progress-bar -o "%TEMP%\DockerInstaller.exe" "https://desktop.docker.com/win/main/amd64/Docker%%20Desktop%%20Installer.exe"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='Continue'; try{ Import-Module BitsTransfer -ErrorAction Stop; Start-BitsTransfer -Source 'https://desktop.docker.com/win/main/amd64/Docker%%20Desktop%%20Installer.exe' -Destination '%TEMP%\DockerInstaller.exe' } catch { Invoke-WebRequest -Uri 'https://desktop.docker.com/win/main/amd64/Docker%%20Desktop%%20Installer.exe' -OutFile '%TEMP%\DockerInstaller.exe' -UseBasicParsing }"
)

if not exist "%TEMP%\DockerInstaller.exe" (
    echo  ERREUR : Telechargement echoue.
    echo  Installe Docker manuellement : https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)

REM -- Installation : 'start /w' bloque jusqu'a la fin reelle de       --
REM -- l'installeur (la doc Docker l'exige : le bootstrapper rend la   --
REM -- main avant la fin du vrai processus enfant).                    --
echo  [..] Installation de Docker Desktop ^(plusieurs minutes - ne ferme pas cette fenetre^)...
start /w "" "%TEMP%\DockerInstaller.exe" install --quiet --accept-license --backend=wsl-2
set INSTALL_RC=%errorlevel%

REM -- Journal de diagnostic (l'installeur GUI n'ecrit pas sur stdout, --
REM -- on consigne donc le code de sortie + les chemins utiles).       --
> "%TEMP%\docker_install.log" echo PenToolbox - journal installation Docker Desktop
>> "%TEMP%\docker_install.log" echo Date              : %DATE% %TIME%
>> "%TEMP%\docker_install.log" echo Code de sortie    : !INSTALL_RC!
>> "%TEMP%\docker_install.log" echo Fichier attendu   : "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
>> "%TEMP%\docker_install.log" echo Journaux Docker   : "%LOCALAPPDATA%\Docker" (et "%TEMP%")

REM -- Verification post-installation : le binaire doit exister, --
REM -- quel que soit le code de sortie de l'installeur.          --
set "DOCKER_INSTALLED=0"
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" set "DOCKER_INSTALLED=1"
if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" set "DOCKER_INSTALLED=1"

if not "!INSTALL_RC!"=="0" goto :INSTALL_FAILED
if "!DOCKER_INSTALLED!"=="0" goto :INSTALL_FAILED

REM -- Succes verifie : suppression de l'installeur, PUIS marqueur de --
REM -- reprise, PUIS redemarrage (jamais avant la verification).      --
del "%TEMP%\DockerInstaller.exe" >nul 2>&1
echo installed> "%TEMP%\pentoolbox_post_reboot.flag"

echo.
echo  =================================================
echo   [OK] Docker installe - REDEMARRAGE NECESSAIRE
echo   Apres redemarrage, relance INSTALLER.bat
echo   (il reprendra directement au lancement de Docker)
echo  =================================================
choice /C ON /M "Redemarrer maintenant ? O=Oui N=Non"
if errorlevel 2 (
    echo  Redemarre manuellement puis relance INSTALLER.bat
    pause
    exit /b 0
)
shutdown /r /t 5
exit /b 0

:INSTALL_FAILED
echo.
echo  =================================================
echo   ERREUR : Installation de Docker Desktop echouee
echo  =================================================
echo   Code de sortie installeur : !INSTALL_RC!
echo   Binaire attendu absent    : "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
echo.
echo   Journal PenToolbox : %TEMP%\docker_install.log
echo   Journaux Docker    : %LOCALAPPDATA%\Docker  (et %TEMP%)
echo   Installeur conserve : %TEMP%\DockerInstaller.exe  (pour diagnostic)
echo.
echo   Aucun marqueur de reprise ecrit, aucun redemarrage declenche.
echo   Corrige le probleme puis relance INSTALLER.bat.
echo  =================================================
pause
exit /b 1

:DOCKER_OK
echo  [OK] Docker detecte
del "%TEMP%\pentoolbox_post_reboot.flag" >nul 2>&1

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
