@echo off
echo ================================================
echo   PenToolbox -- Création de l'EXE Windows
echo ================================================
echo.

REM Installe les dépendances
echo [1/3] Installation des dépendances...
pip install -r requirements.txt pyinstaller --quiet

REM Crée le dossier reports (doit exister pour PyInstaller)
if not exist "reports" mkdir reports
if not exist "static" mkdir static

echo [2/3] Compilation en cours (peut prendre 2-3 minutes)...
pyinstaller ^
    --onefile ^
    --name "PenToolbox" ^
    --add-data "templates;templates" ^
    --add-data "static;static" ^
    --hidden-import flask ^
    --hidden-import flask_cors ^
    --hidden-import jinja2 ^
    --hidden-import dns ^
    --hidden-import dns.resolver ^
    --hidden-import werkzeug ^
    --console ^
    app.py

echo.
echo [3/3] Copie des fichiers necessaires...
if not exist "dist\reports" mkdir "dist\reports"
copy README.md dist\README.md >nul 2>&1

echo.
echo ================================================
echo   TERMINE !
echo   Ton EXE est dans : dist\PenToolbox.exe
echo   Livre ce dossier dist\ au client
echo ================================================
pause
