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
python app/app.py
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
python3 app/app.py
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
python3 app/app.py
```

Installer les outils (avec Homebrew) :
```bash
brew install nmap
brew install dnsutils
```

---

## 🔐 Secrets (génération automatique)

> **The `secrets/` folder is not included in the deliverable and is auto-generated on first launch.**

Le dossier `secrets/` n'est **pas livré** : il est régénéré automatiquement au premier
démarrage, sans aucune intervention manuelle. Au premier lancement, l'application crée :

| Fichier | Rôle | Généré par |
|---------|------|------------|
| `.secret_key` | Clé de session Flask | `app/app.py` (au chargement) |
| `.fernet_key` | Chiffrement des rapports / identifiants | `app/app.py` (au chargement) |
| `.users` | Comptes par défaut **admin / pentest2025** et **analyst / analyst2025** (bcrypt) | `load_users()` (au 1ᵉʳ login) |
| `cert.pem` / `key.pem` | Certificat HTTPS auto-signé (mode standalone) | `_ensure_self_signed_cert()` (au démarrage hors Docker) |

Un clone/dézippage neuf fonctionne donc immédiatement. En mode `docker-compose`,
c'est nginx qui termine le TLS, donc `cert.pem`/`key.pem` ne sont pas nécessaires.

---

## Structure du projet

```
pentoolbox/
├── app/
│   └── app.py               ← Application Flask (backend)
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
| ARP / Découverte réseau | arp-scan / nmap -sn | Partiel | ✓ |
| Nmap Scan | nmap (natif) | ✓ (si nmap installé) | ✓ |
| Énumération SMB | enum4linux-ng / smbclient | Via WSL | ✓ |
| Nikto | nikto | Via WSL | ✓ |
| SQLMap | sqlmap | Via WSL | ✓ |
| Hydra (bruteforce) | hydra (user/pass listes + listes intégrées) | Via WSL | ✓ |
| OpenVAS / GVM | gvm-cli (conteneur openvas) | Docker | Docker |
| Metasploit | msfrpcd (conteneur metasploit) | Docker | Docker |
| Exploitation auto | nmap NSE (détection réelle) | ✓ | ✓ |
| **Cracking** (Post-Exploitation) | John the Ripper (jumbo) | Docker | ✓ |
| **Sessions** (Post-Exploitation) | Metasploit RPC (shell/meterpreter) | Docker | Docker |
| Rapports HTML/JSON/CSV/PDF | Python (par utilisateur) | ✓ | ✓ |

---

## Changer les identifiants

Édite `app/app.py`, ligne `USERS` :
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
