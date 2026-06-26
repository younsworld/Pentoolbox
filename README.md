# PenToolbox — Guide d'installation

## Prérequis
- Python 3.10+ (https://python.org)
- pip (inclus avec Python)

---

## 🪟 Windows — Lancement rapide

```
Double-clic sur : LANCER.bat
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

Quatre scripts simples (à lancer depuis le dossier `pentoolbox/`) :

| Script | Rôle |
|--------|------|
| `./linux_setup.sh`  | **Première installation** : télécharge et construit les 4 conteneurs (PenToolbox + OpenVAS + Metasploit + Nginx), affiche la progression et attend qu'ils soient prêts |
| `./linux_start.sh`  | Démarrer PenToolbox (au quotidien) |
| `./linux_stop.sh`   | Arrêter PenToolbox (les données sont conservées) |
| `./linux_status.sh` | Voir l'état des conteneurs |
| `./linux_remove.sh` | **Désinstaller** : supprime conteneurs, réseau et volumes Docker (⚠️ efface la base/feed OpenVAS ; `reports/` et `secrets/` sont conservés) |

```bash
chmod +x linux_*.sh
./linux_setup.sh        # une seule fois, à l'installation
```

Puis ouvre : **https://localhost/** (proxy Nginx) — GUI OpenVAS : https://localhost:9392
> Au premier lancement, OpenVAS synchronise son feed NVT (30–90 min) ; le reste
> de PenToolbox est utilisable immédiatement. Ensuite, `./linux_start.sh` /
> `./linux_stop.sh` suffisent au quotidien.

### ⏱️ Temps d'installation et espace disque

| Ressource | Valeur indicative |
|-----------|-------------------|
| **Téléchargement + build des 4 images** | ~15–30 min (selon le débit ; ~7,4 Go d'images à récupérer) |
| **Synchronisation du feed NVT OpenVAS** (1er démarrage) | +30–90 min en arrière-plan (le reste de PenToolbox est déjà utilisable) |
| **Espace disque requis** | **~40 Go libres** recommandés |

> Détail de l'occupation disque après installation complète (`docker system df`) :
> images ~7,4 Go, volumes Docker ~28,3 Go (base + feed NVT OpenVAS, Metasploit, socket gvmd),
> conteneurs ~0,2 Go — soit **~36 Go au total**. Prévoir une marge → ~40 Go.

### Installer les outils réseau (Linux)
```bash
sudo apt update
sudo apt install nmap dnsutils smbclient nikto sqlmap -y
```
> `dnsutils` fournit `dig`/`nslookup` (DNS Lookup) ; `smbclient` est requis par
> l'énumération SMB. `dnsrecon`, `hydra`, `john` (jumbo), OpenVAS/gvmd et
> Metasploit RPC sont fournis par l'image Docker (`docker-compose up`).

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
│   └── app.py               ← Application Flask (backend, fichier unique)
├── static/
│   └── app.js               ← Frontend (SPA, sans framework)
├── templates/
│   ├── index.html           ← Interface principale
│   └── report_template.html ← Template rapports HTML
├── deploy/
│   ├── docker/              ← Dockerfile, docker-compose.yml, entrypoint.sh
│   ├── nginx/               ← Reverse proxy TLS (nginx.conf)
│   └── openvas/             ← Image OpenVAS/gvmd
├── linux_setup.sh           ← Installation Docker un clic (Linux/Mac)
├── linux_start.sh / linux_stop.sh / linux_status.sh / linux_remove.sh ← Gestion (Linux/Mac)
├── INSTALLER.bat / LANCER.bat / … ← Lanceurs Windows (Docker)
├── config/                  ← .settings.json (préférences, régénéré au runtime)
├── requirements.txt         ← Dépendances Python
├── reports/                 ← Rapports chiffrés (.enc, Fernet) — régénéré au runtime
├── logs/                    ← audit.log (chiffré) — régénéré au runtime
└── secrets/                 ← clés/certs/utilisateurs — non livré, régénéré au 1ᵉʳ run
```

---

## Fonctionnalités

| Module | Outil utilisé | Windows | Linux |
|--------|--------------|---------|-------|
| DNSDumpster | dig / nslookup / Python socket | ✓ | ✓ |
| DNS Lookup | dig / nslookup (repli Python socket) — A/AAAA/MX/NS/TXT/CNAME/ALL | ✓ | ✓ |
| Dnsrecon (recon passive) | dnsrecon — sous-domaines (Certificate Transparency), DNS, emails | Via WSL | ✓ |
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

## Architecture

- **Stack sans build ni framework** : un fichier Flask (`app/app.py`), un fichier JS (`static/app.js`), templates Jinja2.
- **Pattern de route uniforme** : valider l'entrée → `audit()` → `run_cmd()` (wrapper `subprocess`) → renvoyer stdout/stderr en JSON. Un module = une route.
- **Persistance en fichiers plats chiffrés** (pas de base de données) : `secrets/.users`, `reports/*.enc`, `logs/audit.log` (tous Fernet).
- **Auth double** : cookie de session Flask **ou** jeton bearer (`/api/login`), résolus par `require_auth` ; `require_admin` par-dessus.
- **Frontend SPA** : sections par onglets (`showPage()`), appels via `apiFetch()` (ajoute le bearer) ; RBAC côté client cosmétique, l'enforcement réel est serveur.
- **Outils-services** (OpenVAS/gvmd, Metasploit RPC) via conteneurs dédiés.

---

## Sécurité

- Mots de passe **bcrypt** ; comptes / rapports / journal d'audit **chiffrés Fernet** au repos.
- **RBAC** admin/analyst (`require_admin`), isolation des rapports et sessions **par opérateur**.
- **HTTPS** : certificat auto-signé en standalone (`_ensure_self_signed_cert()`), **TLS terminé par nginx** en Docker.
- **Journal d'audit chiffré** (RotatingFileHandler) ; **rate-limiting** du login (5 tentatives / 60 s puis blocage 5 min).
- Validation des cibles sur le chemin privilégié (`_is_safe_scan_target()`) ; clés générées par installation, **jamais versionnées**.

---

## Déploiement (Docker)

```bash
docker-compose up --build   # pentoolbox + nginx (TLS) + openvas + metasploit
```

- Conteneur **non-root** : `entrypoint.sh` (root) `chown` les montages runtime puis `exec gosu pentoolbox` → l'app tourne en **UID 1000**.
- Capacités `NET_ADMIN`/`NET_RAW` + **carve-out sudoers** ciblé pour les scans nmap privilégiés (`-sS/-O/-sU`).
- Accès via **`https://localhost/`** (nginx → `pentoolbox:5000`). `secrets/`, `logs/`, `reports/` régénérés au runtime.

---

## Comptes & mots de passe

Les comptes ne sont **pas** stockés en clair dans le code : ils sont **hachés bcrypt**
et conservés chiffrés (Fernet) dans `secrets/.users`, créés au premier démarrage par
`load_users()`.

Comptes par défaut (à changer au premier lancement) :

| Identifiant | Mot de passe | Rôle |
|-------------|--------------|------|
| `admin`     | `pentest2025`  | admin |
| `analyst`   | `analyst2025`  | analyst |

**Changer un mot de passe / gérer les comptes** se fait depuis l'interface, page
**Utilisateurs** (réservée à l'admin) → bouton *Changer mdp* / *Supprimer*
(route `PUT /api/users/<utilisateur>/password`). Le compte `admin` par défaut est
protégé (non supprimable, mot de passe modifiable uniquement par lui-même).

---

## Licence & cadre légal

- **Usage strictement autorisé** : tests d'intrusion sur des cibles **consenties** uniquement.
- **Conformité RGPD** : chiffrement des données au repos (Fernet), journalisation des actions (audit), minimisation des données conservées.
- Projet **académique** (Mastère Cybersécurité) — fourni à des fins pédagogiques et de recherche défensive.

## Avertissement légal

Cet outil est réservé aux tests de pénétration **autorisés**.
Toute utilisation non autorisée est illégale.
