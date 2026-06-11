@echo off
echo ================================================
echo   PenToolbox v4.0 -- Lancement Windows
echo ================================================
echo.

REM Vérifie Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python non trouvé. Installe Python 3.10+ depuis python.org
    pause
    exit /b 1
)

echo [*] Installation des dépendances...
pip install -r requirements.txt --quiet

echo [*] Lancement du serveur Flask...
echo [*] Ouvre ton navigateur : http://localhost:5000
echo [*] Ctrl+C pour arrêter
echo.
python app.py
pause
