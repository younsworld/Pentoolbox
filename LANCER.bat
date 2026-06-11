@echo off
setlocal enabledelayedexpansion
title PenToolbox v4.0 — Installation et lancement
color 0B

echo.
echo  ============================================================
echo    ___          _____           _ _
echo   ^|  _ \___ _ ^|_   _^|__   ___ ^| ^| ^|__   _____  __
echo   ^| ^|_) / _ \ '_ ^| ^|/ _ \ / _ \^| ^| '_ \ / _ \ \/ /
echo   ^|  __/  __/ ^| ^| ^| ^| (_) ^| (_) ^| ^| ^|_) ^| (_) ^>  ^<
echo   ^|_^|   \___^|_^| ^|_^|_^|\___/ \___/^|_^|_.__/ \___/_/\_^|
echo.
echo   PenToolbox v4.0 — Installateur automatique
echo  ============================================================
echo.

REM ─── Vérification des droits admin ────────────────────────────────────────
net session >nul 2>&1
if errorlevel 1 (
    echo  [!] Ce script necessite les droits administrateur.
    echo  [!] Clic droit ^> "Executer en tant qu'administrateur"
    echo.
    pause
    exit /b 1
)

REM ─── Vérification Python ──────────────────────────────────────────────────
echo  [*] Verification de Python...
python --version >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
    echo  [+] Python !PYVER! detecte — OK
    goto :PYTHON_OK
)

REM Python pas trouvé, on essaie py aussi
py --version >nul 2>&1
if not errorlevel 1 (
    for /f "tokens=2" %%i in ('py --version 2^>^&1') do set PYVER=%%i
    echo  [+] Python !PYVER! detecte via py.exe — OK
    set PYTHON_CMD=py
    goto :PYTHON_OK
)

REM ─── Téléchargement et installation de Python ─────────────────────────────
echo  [~] Python non trouve — Installation automatique...
echo  [*] Telechargement de Python 3.12 (environ 25 MB)...
echo.

REM Vérifier si curl est disponible (Windows 10+)
curl --version >nul 2>&1
if errorlevel 1 (
    echo  [!] curl absent — utilisation de PowerShell...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe' -OutFile '%TEMP%\python_installer.exe'" 2>nul
) else (
    curl -L -o "%TEMP%\python_installer.exe" "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe" --progress-bar
)

if not exist "%TEMP%\python_installer.exe" (
    echo  [!] Echec du telechargement.
    echo  [!] Verifie ta connexion internet ou installe Python manuellement:
    echo  [!] https://www.python.org/downloads/
    pause
    exit /b 1
)

echo  [*] Installation de Python 3.12 en cours...
echo  [*] (Cette fenetre peut se figer 1-2 minutes, c'est normal)
"%TEMP%\python_installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_launcher=1

REM Refresh PATH
call refreshenv.cmd >nul 2>&1

REM Re-vérification
python --version >nul 2>&1
if errorlevel 1 (
    REM Cherche Python dans les chemins classiques
    set PYPATH=
    for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do set PYPATH=%%d\python.exe
    for /d %%d in ("C:\Python3*") do set PYPATH=%%d\python.exe
    for /d %%d in ("C:\Program Files\Python3*") do set PYPATH=%%d\python.exe
    
    if defined PYPATH (
        echo  [+] Python trouve a: !PYPATH!
        set PYTHON_CMD="!PYPATH!"
    ) else (
        echo  [!] Installation Python semble avoir echoue.
        echo  [!] Redemarre ce script apres avoir redemarre Windows.
        echo  [!] Ou installe Python manuellement: https://www.python.org
        pause
        exit /b 1
    )
) else (
    echo  [+] Python 3.12 installe avec succes !
)

:PYTHON_OK
if not defined PYTHON_CMD set PYTHON_CMD=python

REM ─── Vérification pip ─────────────────────────────────────────────────────
echo  [*] Verification de pip...
%PYTHON_CMD% -m pip --version >nul 2>&1
if errorlevel 1 (
    echo  [*] Installation de pip...
    %PYTHON_CMD% -m ensurepip --upgrade >nul 2>&1
)
echo  [+] pip OK

REM ─── Installation des dépendances ─────────────────────────────────────────
echo.
echo  [*] Installation des dependances PenToolbox...
%PYTHON_CMD% -m pip install --upgrade pip --quiet
%PYTHON_CMD% -m pip install flask flask-cors dnspython requests --quiet

if errorlevel 1 (
    echo  [!] Erreur lors de l'installation des dependances.
    echo  [!] Verifie ta connexion internet.
    pause
    exit /b 1
)
echo  [+] Dependances installees !

REM ─── Création dossier reports ─────────────────────────────────────────────
if not exist "reports" mkdir reports
if not exist "static" mkdir static

REM ─── Lancement de l'application ───────────────────────────────────────────
echo.
echo  ============================================================
echo   [+] TOUT EST PRET !
echo   [*] Lancement de PenToolbox...
echo   [*] Le navigateur va s'ouvrir sur http://localhost:5000
echo   [*] Identifiants : admin / pentest2025
echo   [*] Ferme cette fenetre pour arreter l'application
echo  ============================================================
echo.

REM Attendre 2 secondes puis ouvrir le navigateur
timeout /t 2 /nobreak >nul
start "" "http://localhost:5000"

REM Lancer Flask
%PYTHON_CMD% app.py

echo.
echo  [*] PenToolbox arrete.
pause
