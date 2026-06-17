"""
PenToolbox v4.0 — Version EXE / Déploiement client
Ce fichier remplace app.py pour la version packagée.
Il ouvre automatiquement le navigateur et gère le chemin des ressources.
"""

import sys
import os
import threading
import webbrowser
import time

# ── Gestion du chemin des ressources (PyInstaller) ──────────────────────────
def resource_path(relative_path):
    """Retourne le chemin absolu — fonctionne en dev ET en .exe PyInstaller."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

# ── Dossier reports dans le répertoire courant (pas dans le .exe) ────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Import Flask avec les bons chemins ──────────────────────────────────────
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_cors import CORS
import subprocess, socket, json, uuid, datetime, platform, shutil, re

app = Flask(
    __name__,
    template_folder=resource_path('templates'),
    static_folder=resource_path('static'),
)
app.secret_key = "pentoolbox_secret_2025_changeme"
CORS(app)

# ── Même code que app.py (copié ici pour le bundle) ─────────────────────────
USERS = {
    "admin": "pentest2025",
    "analyst": "analyst2025",
}

def is_tool_available(tool):
    return shutil.which(tool) is not None

def run_cmd(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[!] Timeout après {timeout}s"
    except Exception as e:
        return f"[!] Erreur: {str(e)}"

# ── Toutes les routes sont identiques à app.py ──────────────────────────────
# (copie le contenu de app.py ici ou importe-le)
# Pour simplifier, ce fichier importe app.py directement :

# ── Ouverture automatique du navigateur ──────────────────────────────────────
def open_browser():
    time.sleep(1.5)  # Attend que Flask démarre
    webbrowser.open("http://localhost:5000")
    print("[*] Navigateur ouvert automatiquement")

# ── Point d'entrée ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  PenToolbox v4.0 — Démarrage")
    print("=" * 60)
    print(f"  OS     : {platform.system()} {platform.release()}")
    print(f"  Python : {platform.python_version()}")
    print(f"  Rapports : {REPORTS_DIR}")
    print("=" * 60)
    print("  Ouverture du navigateur dans 2 secondes...")
    print("  Ferme cette fenêtre pour arrêter le serveur")
    print("=" * 60)

    # Lance le navigateur dans un thread séparé
    threading.Thread(target=open_browser, daemon=True).start()

    # Lance Flask
    from app import app as flask_app
    flask_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
