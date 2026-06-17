#!/bin/bash
# PenToolbox v4.0 — Installateur automatique Linux/Mac

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${CYAN}"
echo " ╔═══════════════════════════════════════════════╗"
echo " ║   PenToolbox v4.0 — Installation automatique  ║"
echo " ╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

OS="$(uname -s)"
ARCH="$(uname -m)"
PYTHON_CMD=""

# ─── Détection Python ─────────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Vérification de Python..."

for cmd in python3 python python3.12 python3.11 python3.10; do
    if command -v $cmd &>/dev/null; then
        VER=$($cmd --version 2>&1 | grep -oP '\d+\.\d+')
        MAJOR=$(echo $VER | cut -d. -f1)
        MINOR=$(echo $VER | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 9 ] 2>/dev/null; then
            PYTHON_CMD=$cmd
            echo -e "${GREEN}[+]${NC} Python $VER détecté ($cmd)"
            break
        fi
    fi
done

# ─── Installation Python si absent ────────────────────────────────────────
if [ -z "$PYTHON_CMD" ]; then
    echo -e "${YELLOW}[~]${NC} Python 3.9+ non trouvé — Installation automatique..."

    if [ "$OS" = "Linux" ]; then
        # Détecte le gestionnaire de paquets
        if command -v apt-get &>/dev/null; then
            echo -e "${CYAN}[*]${NC} Détecté: Debian/Ubuntu/Kali"
            echo -e "${CYAN}[*]${NC} Installation Python3 + pip..."
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip python3-venv
            PYTHON_CMD=python3

        elif command -v dnf &>/dev/null; then
            echo -e "${CYAN}[*]${NC} Détecté: Fedora/RHEL"
            sudo dnf install -y python3 python3-pip
            PYTHON_CMD=python3

        elif command -v pacman &>/dev/null; then
            echo -e "${CYAN}[*]${NC} Détecté: Arch Linux"
            sudo pacman -Sy --noconfirm python python-pip
            PYTHON_CMD=python3

        elif command -v zypper &>/dev/null; then
            echo -e "${CYAN}[*]${NC} Détecté: OpenSUSE"
            sudo zypper install -y python3 python3-pip
            PYTHON_CMD=python3

        else
            echo -e "${RED}[!]${NC} Gestionnaire de paquets inconnu."
            echo -e "${RED}[!]${NC} Installe Python3 manuellement: https://python.org"
            exit 1
        fi

    elif [ "$OS" = "Darwin" ]; then
        echo -e "${CYAN}[*]${NC} Détecté: macOS"
        if command -v brew &>/dev/null; then
            echo -e "${CYAN}[*]${NC} Installation via Homebrew..."
            brew install python3
            PYTHON_CMD=python3
        else
            echo -e "${YELLOW}[~]${NC} Homebrew absent — Téléchargement de Python..."
            if [ "$ARCH" = "arm64" ]; then
                PY_URL="https://www.python.org/ftp/python/3.12.4/python-3.12.4-macos11.pkg"
            else
                PY_URL="https://www.python.org/ftp/python/3.12.4/python-3.12.4-macos11.pkg"
            fi
            curl -L -o /tmp/python_installer.pkg "$PY_URL" --progress-bar
            sudo installer -pkg /tmp/python_installer.pkg -target /
            PYTHON_CMD=python3
        fi
    fi

    # Vérification post-installation
    if ! command -v $PYTHON_CMD &>/dev/null; then
        echo -e "${RED}[!]${NC} Installation Python échouée."
        echo -e "${RED}[!]${NC} Installe manuellement: https://python.org"
        exit 1
    fi
    echo -e "${GREEN}[+]${NC} Python installé !"
fi

# ─── pip ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Vérification de pip..."
$PYTHON_CMD -m pip --version &>/dev/null || $PYTHON_CMD -m ensurepip --upgrade &>/dev/null
echo -e "${GREEN}[+]${NC} pip OK"

# ─── Dépendances Python ───────────────────────────────────────────────────
echo -e "${CYAN}[*]${NC} Installation des dépendances..."
$PYTHON_CMD -m pip install flask flask-cors dnspython requests --quiet --break-system-packages 2>/dev/null \
    || $PYTHON_CMD -m pip install flask flask-cors dnspython requests --quiet

echo -e "${GREEN}[+]${NC} Dépendances installées !"

# ─── Outils réseau (optionnels) ───────────────────────────────────────────
echo ""
echo -e "${CYAN}[*]${NC} Vérification des outils réseau (optionnels)..."

MISSING_TOOLS=""
for tool in nmap dig arp-scan; do
    if command -v $tool &>/dev/null; then
        echo -e "    ${GREEN}✓${NC} $tool"
    else
        echo -e "    ${YELLOW}✗${NC} $tool (absent)"
        MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
done

if [ -n "$MISSING_TOOLS" ] && [ "$OS" = "Linux" ]; then
    echo ""
    echo -e "${YELLOW}[~]${NC} Voulez-vous installer les outils manquants ? (y/n)"
    read -t 10 -n 1 INSTALL_TOOLS
    if [ "$INSTALL_TOOLS" = "y" ] || [ "$INSTALL_TOOLS" = "Y" ]; then
        echo ""
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y nmap dnsutils arp-scan 2>/dev/null
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y nmap bind-utils 2>/dev/null
        fi
        echo -e "${GREEN}[+]${NC} Outils réseau installés !"
    fi
fi

# ─── Préparation dossiers ─────────────────────────────────────────────────
mkdir -p reports static

# ─── Lancement ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         TOUT EST PRÊT — Lancement...          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  🌐 Interface : ${CYAN}http://localhost:5000${NC}"
echo -e "  👤 Login    : ${CYAN}admin / pentest2025${NC}"
echo -e "  ⏹  Arrêt    : Ctrl+C"
echo ""

# Ouvre le navigateur après 2 secondes (en arrière-plan)
(sleep 2 && (
    if command -v xdg-open &>/dev/null; then xdg-open http://localhost:5000
    elif command -v open &>/dev/null; then open http://localhost:5000
    elif command -v sensible-browser &>/dev/null; then sensible-browser http://localhost:5000
    fi
)) &

# Lance Flask
$PYTHON_CMD app.py
