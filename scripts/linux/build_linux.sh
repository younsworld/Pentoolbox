#!/bin/bash
# Script desormais dans scripts/linux/ -> on revient a la racine du projet
# pour que tous les chemins relatifs ci-dessous (reports, static, templates,
# app.py, README.md, dist/...) restent corrects.
cd "$(dirname "$0")/../.." || exit 1

echo "================================================"
echo "  PenToolbox -- Build Linux standalone"
echo "================================================"

# Dépendances
echo "[1/3] Installation des dépendances..."
pip3 install -r requirements.txt pyinstaller --quiet

# Dossiers requis
mkdir -p reports static

echo "[2/3] Compilation..."
pyinstaller \
    --onefile \
    --name "PenToolbox" \
    --add-data "templates:templates" \
    --add-data "static:static" \
    --hidden-import flask \
    --hidden-import flask_cors \
    --hidden-import jinja2 \
    --hidden-import dns \
    --hidden-import dns.resolver \
    --hidden-import werkzeug \
    --console \
    app/app.py

echo "[3/3] Finalisation..."
mkdir -p dist/reports
cp README.md dist/ 2>/dev/null

chmod +x dist/PenToolbox

echo ""
echo "================================================"
echo "  TERMINÉ !"
echo "  Binaire : dist/PenToolbox"
echo "  Lance avec : ./dist/PenToolbox"
echo "================================================"
