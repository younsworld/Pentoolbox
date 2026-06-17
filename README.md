# PenToolbox v4.0 — Guide d'installation

## Prérequis
- Python 3.10+ (https://python.org)
- pip (inclus avec Python)

---

## 🪟 Windows — Lancement rapide

```
Double-clic sur : lancer_windows.bat
```

Ou en ligne de commande :
```
pip install -r requirements.txt
python app.py
```

Puis ouvre : http://localhost:5000

Identifiants par défaut : **admin / pentest2025**

---

## 🐧 Linux / Kali / Ubuntu

```bash
chmod +x lancer_linux.sh
./lancer_linux.sh
```

Ou manuellement :
```bash
pip3 install -r requirements.txt
python3 app.py
```

### Installer les outils réseau (Linux)
```bash
sudo apt update
sudo apt install nmap dnsutils arp-scan nikto sqlmap -y
```

---

## 🍎 Mac

```bash
pip3 install -r requirements.txt
python3 app.py
```

Installer les outils (avec Homebrew) :
```bash
brew install nmap
brew install dnsutils
```

---

## Structure du projet

```
pentoolbox/
├── app.py                   ← Application Flask (backend)
├── requirements.txt         ← Dépendances Python
├── lancer_windows.bat       ← Lanceur Windows
├── lancer_linux.sh          ← Lanceur Linux/Mac
├── templates/
│   ├── index.html           ← Interface principale
│   └── report_template.html ← Template rapports HTML
└── reports/                 ← Rapports sauvegardés (JSON)
```

---

## Fonctionnalités

| Module | Outil utilisé | Windows | Linux |
|--------|--------------|---------|-------|
| DNSDumpster | dig / nslookup / Python socket | ✓ | ✓ |
| DNS Lookup | dig / nslookup | ✓ | ✓ |
| ARP Scan | arp-scan / nmap -sn | Partiel | ✓ |
| Nmap Scan | nmap (natif) | ✓ (si nmap installé) | ✓ |
| Nikto | nikto | Via WSL | ✓ |
| SQLMap | sqlmap | Via WSL | ✓ |
| Exploitation | Simulation | ✓ | ✓ |
| Rapports HTML/JSON/CSV | Python | ✓ | ✓ |

---

## Changer les identifiants

Édite `app.py`, ligne `USERS` :
```python
USERS = {
    "admin": "votre_mot_de_passe",
    "analyst": "autre_mdp",
}
```

---

## Avertissement légal

Cet outil est réservé aux tests de pénétration **autorisés**.
Toute utilisation non autorisée est illégale.
