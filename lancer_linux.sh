#!/bin/bash
echo "================================================"
echo "  PenToolbox v4.0 -- Lancement Linux/Mac"
echo "================================================"

# Vérifie Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 non trouvé. Lance: sudo apt install python3 python3-pip"
    exit 1
fi

# Installation dépendances
echo "[*] Installation des dépendances Python..."
pip3 install -r requirements.txt --quiet

# Vérifie les outils optionnels
echo ""
echo "[*] Vérification des outils réseau..."
for tool in nmap dig arp-scan nikto sqlmap; do
    if command -v $tool &> /dev/null; then
        echo "    ✓ $tool"
    else
        echo "    ✗ $tool (absent — installe: sudo apt install $tool)"
    fi
done

echo ""
echo "[*] Lancement du serveur Flask..."
echo "[*] Ouvre : http://localhost:5000"
echo "[*] Ctrl+C pour arrêter"
echo ""
python3 app.py
