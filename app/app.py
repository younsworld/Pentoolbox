"""
PenToolbox v4.0 — Application Flask
Securite : bcrypt + audit logs + session timeout + rate limiting + Fernet + gestion users
"""

from flask import Flask, render_template, request, jsonify, session, send_file
from flask_cors import CORS
from cryptography.fernet import Fernet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm
from io import BytesIO
import subprocess, socket, json, os, uuid, datetime, platform, shutil, re, secrets, bcrypt, time, threading, shlex, ipaddress, tempfile
import xml.etree.ElementTree as ET
import logging
from logging.handlers import RotatingFileHandler

# app.py vit dans app/ (cf. restructuration, CLAUDE.md) — templates/ et
# static/ restent a la racine du projet, donc Flask doit etre informe
# explicitement (sinon il chercherait app/templates/ et app/static/ par
# defaut, relatif a ce fichier, et 404 partout).
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "templates"),
            static_folder=os.path.join(BASE_DIR, "static"))
# debug=False below means Jinja wouldn't otherwise auto-reload index.html when the
# bind-mounted source file changes (it caches the compiled template per process).
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── SECRET KEY unique par poste ───────────────────────────────────────────────
# Secrets (cles, identifiants chiffres, certs) et config non-sensible separes
# du code et du reste du projet — voir CLAUDE.md pour le detail de la
# reorganisation. Crees ici (et pas seulement par mkdir manuel) pour qu'une
# install neuve les retrouve aussi.
SECRETS_DIR = os.path.join(BASE_DIR, "secrets")
CONFIG_DIR  = os.path.join(BASE_DIR, "config")
os.makedirs(SECRETS_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
try:
    os.chmod(SECRETS_DIR, 0o700)
except Exception:
    pass
SECRET_KEY_FILE = os.path.join(SECRETS_DIR, ".secret_key")
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(app.secret_key)
    print("  [+] Secret key generee -> .secret_key")

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Secure=True seulement sous Docker: c'est le seul cas ou nginx termine TLS en
# face (docker-compose.yml service "nginx", port 443) et ou le navigateur charge
# donc toujours la page en HTTPS. En mode standalone (LANCER.sh/python app.py,
# cf. CLAUDE.md "Running it"), il n'y a pas de proxy TLS devant Flask — passer
# Secure=True dans ce cas empecherait le navigateur de renvoyer le cookie et
# casserait le login en http://localhost:5000.
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("DOCKER_ENV"))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)

if os.environ.get("DOCKER_ENV"):
    # nginx (TLS) -> Flask (HTTP en clair sur le reseau Docker interne):
    # ProxyFix permet a Flask de voir le scheme/host d'origine via les
    # en-tetes X-Forwarded-* poses par nginx (cf. nginx/nginx.conf), pour que
    # request.is_secure/url_for refletent correctement https.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

CORS(app, supports_credentials=True, origins=[
    "http://localhost:5000", "http://127.0.0.1:5000",
    "http://localhost", "http://127.0.0.1",
    "https://localhost", "https://127.0.0.1",
])

REPORTS_DIR   = os.path.join(BASE_DIR, "reports")
LOGS_DIR      = os.path.join(BASE_DIR, "logs")
USERS_FILE    = os.path.join(SECRETS_DIR, ".users")
AUDIT_FILE    = os.path.join(LOGS_DIR, "audit.log")
FERNET_FILE   = os.path.join(SECRETS_DIR, ".fernet_key")
SETTINGS_FILE = os.path.join(CONFIG_DIR, ".settings.json")
DASHBOARD_STATS_FILE = os.path.join(SECRETS_DIR, ".dashboard_stats")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# RotatingFileHandler plutot qu'un append direct: audit.log grossissait sans
# limite (cf. audit du hardening). %(message)s pur car la ligne est deja
# entierement formatee par audit() ci-dessous (timestamp/action/user/ip) —
# pas de prefixe logging supplementaire, format de fichier identique a avant.
_audit_logger = logging.getLogger("pentoolbox.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False
_audit_handler = RotatingFileHandler(AUDIT_FILE, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_audit_handler)

# ── FERNET — chiffrement des rapports ────────────────────────────────────────
if os.path.exists(FERNET_FILE):
    with open(FERNET_FILE, "rb") as f:
        FERNET = Fernet(f.read())
else:
    key = Fernet.generate_key()
    with open(FERNET_FILE, "wb") as f:
        f.write(key)
    FERNET = Fernet(key)
    print("  [+] Cle Fernet generee -> .fernet_key")

def encrypt_report(data: dict) -> bytes:
    return FERNET.encrypt(json.dumps(data, ensure_ascii=False).encode())

def decrypt_report(data: bytes) -> dict:
    return json.loads(FERNET.decrypt(data).decode())

# ── LOGS CHIFFRES (audit logs en AES-128) ─────────────────────────────────────
def log_encrypted(message: str):
    """Écrit une ligne chiffrée dans audit.log (protection at-rest)"""
    try:
        encrypted = FERNET.encrypt(message.encode()).decode()
        _audit_logger.info(encrypted)
    except Exception as e:
        _audit_logger.error(f"Erreur chiffrement log: {e}")
        _audit_logger.info(message)  # Fallback: log non chiffré si erreur

def read_encrypted_logs(limit: int = 100) -> list:
    """Lit et déchiffre les logs audit"""
    logs = []
    try:
        if not os.path.exists(AUDIT_FILE):
            return []
        with open(AUDIT_FILE, 'r') as f:
            lines = f.readlines()[-limit:]  # Dernières N lignes
        for line in lines:
            s = line.strip()
            if not s:
                continue
            try:
                logs.append(FERNET.decrypt(s).decode())
            except Exception:
                # Rétro-compat : d'anciennes lignes ont pu être écrites en clair
                # (fallback de log_encrypted, ou version antérieure). Une vraie
                # entrée d'audit commence par "[AAAA-MM-JJ" -> on l'affiche telle
                # quelle plutôt que de la marquer "corrompue".
                if re.match(r"^\[\d{4}-\d{2}-\d{2}", s):
                    logs.append(s)
                else:
                    logs.append(f"[!] Ligne illisible (clé Fernet différente ?): {s[:40]}…")
    except Exception as e:
        logs.append(f"[!] Erreur lecture logs: {e}")
    return logs

# ── GESTION UTILISATEURS (fichier .users chiffre) ────────────────────────────
def load_users() -> dict:
    """
    Structure users: { "username": {"hash": "...", "role": "admin|analyst"} }
    Retro-compatible avec l'ancien format { "username": "hash" }
    """
    if not os.path.exists(USERS_FILE):
        default = {
            "admin":   {"hash": bcrypt.hashpw(b"pentest2025", bcrypt.gensalt()).decode(), "role": "admin"},
            "analyst": {"hash": bcrypt.hashpw(b"analyst2025", bcrypt.gensalt()).decode(), "role": "analyst"},
        }
        save_users(default)
        return default
    try:
        data = json.loads(FERNET.decrypt(open(USERS_FILE, "rb").read()).decode())
        # Migration ancien format
        migrated = False
        for u, v in data.items():
            if isinstance(v, str):
                data[u] = {"hash": v, "role": "admin" if u == "admin" else "analyst"}
                migrated = True
        if migrated:
            save_users(data)
        return data
    except:
        return {}

def save_users(users: dict):
    with open(USERS_FILE, "wb") as f:
        f.write(FERNET.encrypt(json.dumps(users).encode()))

# ── PARAMETRES APPLICATIFS (.settings.json, magasin cle/valeur generique) ────
# Meme philosophie flat-file que load_users()/reports/*.enc, mais sans
# chiffrement: ce sont des reglages operationnels (ex: allowed_exploit_subnets),
# pas des secrets - pas de raison d'imposer le cout/complexite de Fernet ici.
# Permet de changer un reglage a chaud (admin) sans redemarrer le conteneur,
# contrairement aux variables d'environnement.
def load_settings() -> dict:
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(settings: dict):
    # Ecriture atomique (fichier temporaire + os.replace) plutot qu'un open("w")
    # direct, pour deux raisons:
    #  1) on ne laisse jamais un .settings.json tronque si l'ecriture echoue en
    #     cours de route (le rename est atomique cote POSIX).
    #  2) os.replace() remplace la cible via un rename dans le repertoire: il ne
    #     demande le droit d'ecriture que sur le REPERTOIRE config/, pas sur le
    #     fichier existant. Un .settings.json laisse en root:root par un ancien
    #     run root/Docker (cf. l'artefact root:root d'audit.log dans
    #     RESTRUCTURE_SUMMARY) redevient donc writable+possede par l'utilisateur
    #     courant des le premier save, au lieu de faire planter la route en 500.
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_FILE)

def get_setting(key: str, default=None):
    return load_settings().get(key, default)

def set_setting(key: str, value):
    settings = load_settings()
    settings[key] = value
    save_settings(settings)

# ── RAPPORTS AUTOMATIQUES — préférences par outil ─────────────────────────────
# Chaque outil peut générer un rapport automatiquement en fin de scan (cf.
# Improvement 3). Activé par défaut ; désactivable par l'utilisateur via
# /api/settings/auto-report. Stocké dans .settings.json sous "auto_report".
AUTO_REPORT_TOOLS = ["nmap", "enum4linux", "recon", "dnsdumpster", "metasploit",
                     "exploit_auto", "sqlmap", "hydra", "nikto", "john", "openvas"]

def _auto_report_enabled(tool: str) -> bool:
    prefs = get_setting("auto_report", {}) or {}
    return bool(prefs.get(tool, True))  # défaut: activé

def _maybe_auto_report(tool, target, output, modules_run, vulnerabilities=None, operator=None):
    """Génère un rapport automatique en fin de scan SI (1) l'auto-report est
    activé pour cet outil et (2) l'appelant juge qu'il y a des résultats (il ne
    nous appelle que dans ce cas — pas de rapport vide/d'échec, cf. Improvement
    3). Renvoie report_id ou None. Centralise le motif pour tous les outils."""
    if not _auto_report_enabled(tool):
        return None
    try:
        rid, _ = _save_scan_report(target=target, scan_output=output,
                                   vulnerabilities=vulnerabilities or [],
                                   modules_run=modules_run, operator=operator, auto=True)
        return rid
    except Exception:
        return None

def get_user_role(username: str) -> str:
    users = load_users()
    user = users.get(username, {})
    if isinstance(user, dict):
        return user.get("role", "analyst")
    return "analyst"

def check_password(username: str, password: str) -> bool:
    users = load_users()
    user = users.get(username)
    if not user:
        return False
    hashed = user["hash"] if isinstance(user, dict) else user
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

# ── AUDIT LOGS ────────────────────────────────────────────────────────────────
def audit(action: str, user: str = None, details: str = ""):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Le scan OpenVAS tourne dans un thread de fond (hors contexte de requete
    # Flask), donc `request`/`session` levent RuntimeError ici -> fallback "system".
    try:
        ip = request.remote_addr
    except RuntimeError:
        ip = "system"
    # get_current_user() consulte flask.g (rempli par require_auth) AVANT la
    # session: indispensable pour l'auth par token Bearer (mode principal du SPA
    # via apiFetch), ou l'utilisateur n'est PAS dans la session cookie -> sans ca
    # toutes les actions token-authentifiees etaient tracees user=unknown.
    # Les workers de fond (OpenVAS/MSF) passent toujours user= explicitement,
    # donc le court-circuit `user or ...` evite d'appeler g/session hors requete.
    try:
        u = user or get_current_user()
    except Exception:
        u = user or "unknown"
    # Ligne deja entierement formatee; le RotatingFileHandler (cf. _audit_logger
    # plus haut) ajoute lui-meme le saut de ligne via son terminator, donc pas
    # de "\n" ici sinon on doublerait les retours a la ligne dans audit.log.
    line = f"[{now}] {action:<22} user={u:<15} ip={ip:<15} {details}"
    try:
        log_encrypted(line)
    except Exception:
        pass
    print(f"  [AUDIT] {line}")

# ── RATE LIMITING — anti brute force ─────────────────────────────────────────
LOGIN_ATTEMPTS = {}   # { ip: {"count": int, "first_time": float, "blocked_until": float} }
MAX_ATTEMPTS   = 5    # tentatives max avant blocage
BLOCK_DURATION = 300  # secondes de blocage (5 min)
WINDOW         = 60   # fenetre de temps (1 min)

def check_rate_limit(ip: str) -> tuple:
    """Retourne (autorise: bool, message: str, secondes_restantes: int)"""
    now = time.time()
    data = LOGIN_ATTEMPTS.get(ip, {"count": 0, "first_time": now, "blocked_until": 0})

    # Encore bloque ?
    if data["blocked_until"] > now:
        remaining = int(data["blocked_until"] - now)
        return False, f"Trop de tentatives. Reessayez dans {remaining}s", remaining

    # Reset si fenetre expiree
    if now - data["first_time"] > WINDOW:
        data = {"count": 0, "first_time": now, "blocked_until": 0}

    return True, "ok", 0

def record_failed_attempt(ip: str):
    now  = time.time()
    data = LOGIN_ATTEMPTS.get(ip, {"count": 0, "first_time": now, "blocked_until": 0})
    if now - data["first_time"] > WINDOW:
        data = {"count": 0, "first_time": now, "blocked_until": 0}
    data["count"] += 1
    if data["count"] >= MAX_ATTEMPTS:
        data["blocked_until"] = now + BLOCK_DURATION
        audit("RATE_LIMIT_BLOCK", user="system", details=f"ip={ip} blocked={BLOCK_DURATION}s")
    LOGIN_ATTEMPTS[ip] = data

def reset_attempts(ip: str):
    LOGIN_ATTEMPTS.pop(ip, None)

# ── TOKENS ACTIFS ─────────────────────────────────────────────────────────────
ACTIVE_TOKENS = {}

# ── UTILITAIRES ───────────────────────────────────────────────────────────────
def is_tool_available(tool): return shutil.which(tool) is not None

def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return f"[!] Timeout apres {timeout}s"
    except Exception as e:
        return f"[!] Erreur: {e}"

# ── OPENVAS / GVM — config & helpers GMP ─────────────────────────────────────
OPENVAS_HOST     = os.environ.get("OPENVAS_HOST", "openvas")
OPENVAS_GMP_PORT = os.environ.get("OPENVAS_PORT", "9390")
OPENVAS_USER     = os.environ.get("OPENVAS_USER", "admin")
OPENVAS_PASSWORD = os.environ.get("OPENVAS_PASSWORD", "admin")
OPENVAS_SOCKET   = os.environ.get("OPENVAS_SOCKET", "/run/gvmd/gvmd.sock")
# UUID standard du scan config "Full and fast" livre par tous les flux Greenbone.
OPENVAS_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
# gvmd refuse create_target sans PORT_LIST/PORT_RANGE ("400 One of PORT_LIST and
# PORT_RANGE are required"). Plutot que de coder en dur des UUID de port lists
# (ils peuvent differer entre versions de GVM), on les resout A CHAUD par nom via
# <get_port_lists/> (cf. _get_port_lists / _resolve_port_list_by_name). On ne
# garde ci-dessous que des NOMS (stables d'une version a l'autre) + un UUID de
# repli si jamais la resolution live echoue.
#
# Presets proposes dans le selecteur de l'UI (dans cet ordre). Ce sont les noms
# des port lists Greenbone livrees par defaut.
OPENVAS_PRESET_PORT_LISTS = [
    "All IANA assigned TCP",
    "All IANA assigned TCP and UDP",
    "All TCP and Nmap top 100 UDP",
]
# Selection par defaut quand l'UI ne passe aucune port list.
OPENVAS_DEFAULT_PORT_LIST_NAME = "All TCP and Nmap top 100 UDP"
# UUID de "All TCP and Nmap top 100 UDP" — uniquement un repli si la resolution
# live par nom echoue (ne devrait pas arriver sur un gvmd standard).
OPENVAS_PORT_LIST_ID   = "730ef368-57e2-11e1-a90f-406186ea4fc5"
# Port list custom "Top 100 TCP": absente des flux Greenbone, on la cree au
# besoin (reutilisee par nom si elle existe deja, cf. _ensure_port_list). La
# plage = les 100 ports TCP les plus frequents de nmap (nmap-services).
OPENVAS_TOP100_TCP_NAME  = "Top 100 TCP"
OPENVAS_TOP100_TCP_RANGE = (
    "T:7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,"
    "144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,"
    "873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,"
    "2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,"
    "5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,"
    "8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
)
OPENVAS_MAX_RUNTIME    = 7200  # garde-fou: on arrete de suivre un scan au-dela de 2h

class OpenVASError(Exception):
    """Erreur fonctionnelle OpenVAS/GVM (demon injoignable, feed NVT pas pret, GMP en erreur)."""

# ── METASPLOIT — config & helpers RPC ────────────────────────────────────────
MSF_RPC_HOST     = os.environ.get("MSF_RPC_HOST", "metasploit")
MSF_RPC_PORT     = int(os.environ.get("MSF_RPC_PORT", "55553"))
MSF_RPC_PASSWORD = os.environ.get("MSF_RPC_PASSWORD", "msfpass")
MSF_MAX_RUNTIME  = 180  # garde-fou: ces modules finissent en secondes/minutes, pas en heures

# Restreint les modules exploit/* a des sous-reseaux CIDR explicitement
# autorises (chaine CSV, ex: "192.168.56.0/24,10.141.67.0/24"). Deny-by-default:
# liste vide -> aucun exploit ne peut tourner, quel que soit le target, jusqu'a
# ce que l'operateur declare explicitement son perimetre de labo. C'est un
# controle technique reel (verifie a chaque requete), pas une simple promesse
# documentaire — voir _target_in_allowed_exploit_subnets() et son appel dans
# msf_scan(). Les modules auxiliary/scanner ne sont pas concernes (recon non
# destructive, pas de cible a restreindre).
#
# Valeur modifiable a chaud via PUT /api/settings/subnets (cle "allowed_exploit_subnets"
# dans .settings.json, cf. set_setting()) sans redemarrer le conteneur - utile
# pour changer de labo (ex: 192.168.56.0/24 -> 10.141.67.0/24) sans toucher au
# docker-compose. La variable d'env ALLOWED_EXPLOIT_SUBNETS ne sert plus que de
# valeur de depart tant qu'aucun admin n'a encore enregistre de reglage en base.
def _allowed_exploit_subnets_raw() -> str:
    stored = get_setting("allowed_exploit_subnets")
    if stored is not None:
        return stored
    return os.environ.get("ALLOWED_EXPLOIT_SUBNETS", "")

def _allowed_exploit_subnets() -> list:
    return [s.strip() for s in _allowed_exploit_subnets_raw().split(",") if s.strip()]

def _target_in_allowed_exploit_subnets(target: str) -> bool:
    """
    True si `target` est une adresse IP appartenant a un des reseaux CIDR
    actuellement autorises (cf. _allowed_exploit_subnets()). Refuse
    volontairement les noms d'hote (pas seulement les IP) plutot que de les
    resoudre: une resolution DNS cote serveur ajouterait une dependance non
    maitrisee (DNS rebinding, hote qui resout differemment au moment du scan)
    sur la decision d'autoriser un exploit reel - on ne valide que ce qui est
    verifiable directement.
    """
    subnets = _allowed_exploit_subnets()
    if not subnets:
        return False
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    for subnet in subnets:
        try:
            if target_ip in ipaddress.ip_network(subnet, strict=False):
                return True
        except ValueError:
            continue  # entree CIDR malformee dans la config - ignoree, pas fatale
    return False

# Allow-list explicite des modules exposables a l'UI — c'est ici, pas dans le
# frontend, que se joue la contrainte ethique du labo M1. Le frontend ne fait
# que refleter ce dict via GET /api/msf/modules (select, pas de texte libre,
# et sans jamais exposer "payload" au client) - meme principe que
# applyRBAC() cote JS qui est cosmetique alors que require_admin() cote
# serveur est la vraie barriere (cf. CLAUDE.md): ici la vraie barriere est
# cette whitelist verifiee dans la route, pas ce que le <select> affiche.
#
# Les modules auxiliary/scanner/* sont de la recon non destructive, sans
# restriction de cible. Les modules exploit/* accordent un shell distant —
# leur cible est en plus verifiee contre ALLOWED_EXPLOIT_SUBNETS (cf.
# msf_scan()) et leur payload est fige ici (jamais choisi par le client):
# cmd/unix/interact pour vsftpd (le backdoor sert directement de canal de
# commande, pas besoin de connexion retour), cmd/unix/reverse pour les deux
# autres (shell de base qui se connecte vers LHOST/LPORT).
MSF_ALLOWED_MODULES = {
    # ── Détection de version / fingerprint (recon non destructive) ────────────
    "auxiliary/scanner/portscan/tcp": {
        "label": "TCP Port Scan", "category": "version", "options": ["RHOSTS", "PORTS", "THREADS"],
    },
    "auxiliary/scanner/http/http_version": {
        "label": "HTTP/HTTPS — version serveur", "category": "version", "options": ["RHOSTS", "RPORT"],
    },
    "auxiliary/scanner/ssh/ssh_version": {
        "label": "SSH — version & algorithmes", "category": "version", "options": ["RHOSTS", "RPORT"],
    },
    "auxiliary/scanner/ftp/ftp_version": {
        "label": "FTP — version", "category": "version", "options": ["RHOSTS", "RPORT"],
    },
    "auxiliary/scanner/smb/smb_version": {
        "label": "SMB — version & signature", "category": "version", "options": ["RHOSTS"],
    },
    # ── Détection de CVE célèbres (scanners, non destructif) ──────────────────
    "auxiliary/scanner/smb/smb_ms17_010": {
        "label": "Détection EternalBlue (MS17-010)", "category": "detection", "options": ["RHOSTS", "RPORT"],
    },
    "auxiliary/scanner/rdp/cve_2019_0708_bluekeep": {
        "label": "Détection BlueKeep (CVE-2019-0708)", "category": "detection", "options": ["RHOSTS", "RPORT"],
    },
    "auxiliary/scanner/ssl/openssl_heartbleed": {
        "label": "Détection Heartbleed (CVE-2014-0160)", "category": "detection", "options": ["RHOSTS", "RPORT"],
    },
    "auxiliary/scanner/http/log4shell_scanner": {
        "label": "Détection Log4Shell (CVE-2021-44228)", "category": "detection", "options": ["RHOSTS", "RPORT", "TARGETURI"],
    },
    "auxiliary/scanner/http/apache_mod_cgi_bash_env": {
        "label": "Détection Shellshock (CVE-2014-6271)", "category": "detection", "options": ["RHOSTS", "RPORT", "TARGETURI"],
    },
    # ── Exploits (shell distant -> gate ALLOWED_EXPLOIT_SUBNETS + payload figé) ─
    "exploit/unix/ftp/vsftpd_234_backdoor": {
        "label": "Exploit: vsftpd v2.3.4 Backdoor", "category": "exploit",
        "options": ["RHOSTS", "RPORT"],
        "payload": "cmd/unix/interact",
    },
    "exploit/unix/irc/unreal_ircd_3281_backdoor": {
        "label": "Exploit: UnrealIRCd Backdoor", "category": "exploit",
        "options": ["RHOSTS", "RPORT", "LHOST", "LPORT"],
        "payload": "cmd/unix/reverse",
    },
    "exploit/multi/samba/usermap_script": {
        "label": "Exploit: Samba usermap_script", "category": "exploit",
        "options": ["RHOSTS", "RPORT", "LHOST", "LPORT"],
        "payload": "cmd/unix/reverse",
    },
    "exploit/multi/http/apache_mod_cgi_bash_env_exec": {
        "label": "Exploit: Shellshock (CVE-2014-6271)", "category": "exploit",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "LHOST", "LPORT"],
        "payload": "linux/x86/meterpreter/reverse_tcp",
    },
    "exploit/windows/smb/ms17_010_eternalblue": {
        "label": "Exploit: EternalBlue (MS17-010)", "category": "exploit",
        "options": ["RHOSTS", "LHOST", "LPORT"],
        "payload": "windows/x64/meterpreter/reverse_tcp",
    },
}
# NB volontaire: BlueKeep est exposé en DÉTECTION uniquement (scanner ci-dessus),
# pas en RCE — exploit/windows/rdp/cve_2019_0708_bluekeep_rce existe dans le
# framework mais provoque fréquemment un BSOD de la cible (instable/destructif),
# au même titre que Log4Shell/Heartbleed traités en détection seule.

class MetasploitError(Exception):
    """Erreur fonctionnelle Metasploit (RPC injoignable, module/option invalide)."""

_msf_client_cache = {"client": None}

def _msf_client():
    """
    Cree (ou reutilise) un MsfRpcClient. Mis en cache au niveau process car
    login() cree un token RPC a chaque appel - pas la peine d'en generer un
    nouveau a chaque requete. Recree automatiquement si le cache est vide
    (ex: apres une erreur d'auth/connexion, cf. appelants ci-dessous).
    """
    if _msf_client_cache["client"] is None:
        from pymetasploit3.msfrpc import MsfRpcClient
        try:
            _msf_client_cache["client"] = MsfRpcClient(
                MSF_RPC_PASSWORD, server=MSF_RPC_HOST, port=MSF_RPC_PORT, ssl=False,
            )
        except Exception as e:
            raise MetasploitError(
                f"msfrpcd injoignable sur {MSF_RPC_HOST}:{MSF_RPC_PORT} - "
                f"le conteneur Metasploit est-il demarre ? ({e})"
            )
    return _msf_client_cache["client"]

def _msf_probe(timeout=10):
    """Sonde rapide (core.version) pour distinguer 'RPC pas pret' d'une vraie erreur de scan."""
    try:
        _msf_client().core.version
    except MetasploitError:
        raise
    except Exception as e:
        _msf_client_cache["client"] = None  # force une reconnexion au prochain appel
        raise MetasploitError(f"msfrpcd injoignable sur {MSF_RPC_HOST}:{MSF_RPC_PORT} - {e}")

_msf_modules_cache = {"set": None, "ts": 0}

def _msf_available_set(ttl=300):
    """Ensemble des modules réellement présents dans msfrpcd (préfixés
    exploit/ ou auxiliary/), mis en cache (TTL) car la liste complète est
    volumineuse (~3600 modules). Renvoie None si le RPC est injoignable ->
    permet à l'UI d'afficher 'RPC injoignable' plutôt qu'un faux 'absent'."""
    now = time.time()
    if _msf_modules_cache["set"] is not None and now - _msf_modules_cache["ts"] < ttl:
        return _msf_modules_cache["set"]
    try:
        c = _msf_client()
        avail = {"exploit/" + m for m in c.modules.exploits} | {"auxiliary/" + m for m in c.modules.auxiliary}
        _msf_modules_cache.update(set=avail, ts=now)
        return avail
    except Exception:
        return None

def _gvm_cli(xml_cmd: str, timeout: int = 30) -> str:
    """
    Envoie une commande GMP (XML) a gvmd via gvm-cli, en reutilisant run_cmd()
    comme toutes les autres routes -> meme comportement de timeout.

    Passe par le socket unix partage (volume gvmd_socket monte sur /run/gvmd
    dans les deux conteneurs) plutot que TLS/9390: gvmd 26.x refuse de cumuler
    --listen/--listen2 avec --unix-socket ("gvmd: --listen or --listen2 given
    with --unix-socket", crash-loop immediat) et --unix-socket est necessaire
    a gsad (--munix-socket) -> le conteneur openvas n'expose donc plus aucun
    port GMP TCP (voir GVMD_ARGS dans docker-compose.yml, --listen-mode=666
    pour rendre le socket accessible cross-conteneur sans alignement uid/gid).

    gvm-cli refuse de s'executer en root ("This tool MUST NOT be run as root
    user.", do_not_run_as_root() dans gvm-tools). Le conteneur tournant
    desormais en non-root (USER pentoolbox, uid 1000, cf. durcissement Docker),
    cette contrainte est deja satisfaite -> gvm-cli est lance directement, sans
    `su` ni `sudo`. L'ancien wrapper `su -s /bin/sh nobody -c ...` n'existait
    que parce que le conteneur tournait en root ; depuis le passage en non-root
    il echouait ("Password: su: Authentication failure", su ne pouvant changer
    d'utilisateur sans mot de passe quand on n'est pas root) et est donc inutile
    autant que casse. Le socket gvmd est en mode 666 (--listen-mode ci-dessus),
    accessible a n'importe quel uid : aucun alignement uid/gid ni utilisateur
    dedie (gvm/_gvm/nobody) n'est requis - verifie empiriquement, gvm-cli rend
    <get_version_response status="200"> en tournant directement comme pentoolbox.
    Contrairement a nmap (qui a besoin de PLUS de privilege -> carve-out sudo),
    gvm-cli a besoin de MOINS (non-root), deja acquis -> pas de regle sudoers.
    shlex.quote() reste applique au payload XML pour l'echappement des guillemets.
    """
    cmd = (
        f"gvm-cli --gmp-username {OPENVAS_USER} --gmp-password {OPENVAS_PASSWORD} "
        f"socket --sockpath {OPENVAS_SOCKET} --xml {shlex.quote(xml_cmd)}"
    )
    return run_cmd(cmd, timeout=timeout)

def _gvm_command(xml_cmd: str, timeout: int = 30) -> ET.Element:
    """
    Execute une commande GMP et renvoie la reponse XML parsee.
    Centralise les 3 modes d'echec propres a OpenVAS (vs les autres outils,
    qui sont de simples binaires locaux):
      1) timeout reseau/process -> souvent un feed NVT en cours de synchro
      2) demon injoignable -> conteneur openvas pas (encore) demarre
      3) reponse GMP en erreur -> ex: scan config introuvable car les
         configs par defaut ne sont crees qu'apres le 1er sync des feeds
    """
    raw = _gvm_cli(xml_cmd, timeout=timeout)

    # Trace systematique de la reponse BRUTE (tronquee) avant tout parsing: sans
    # ca, un echec gvmd se resumait cote UI a "XML invalide: line 1 column 0",
    # impossible a diagnostiquer. La reponse reelle (socket absent, "su:
    # Authentication failure" quand l'app n'est pas root, demon arrete, prompt
    # d'auth, octets TLS, feed pas pret...) n'apparaissait nulle part.
    # flush=True: stdout est bufferise quand redirige vers un fichier (lancement
    # non-tty) — sans flush, cette trace de diagnostic pouvait rester coincee
    # dans le buffer et ne jamais apparaitre au moment du depannage.
    print(f"  [GMP] cmd={xml_cmd[:60]!r} -> {raw[:200]!r}", flush=True)

    if raw.startswith("[!] Timeout"):
        raise OpenVASError(
            f"Delai depasse en attendant gvmd ({timeout}s) - le feed NVT est "
            "probablement encore en cours de synchronisation."
        )

    # gvmd injoignable / pas pret: la reponse n'est alors PAS du XML. Plutot que
    # de lister des sous-chaines precises (qui laissaient passer des cas comme
    # un message d'erreur shell -> ET.fromstring -> "XML invalide" illisible), on
    # rejette toute reponse vide ou qui ne commence pas par '<', en remontant
    # l'extrait brut et les causes concretes. Une vraie reponse GMP (meme en
    # erreur, ex: <get_version_response status="400"/>) commence par '<' et passe
    # ce filtre pour etre traitee par la verification de statut plus bas.
    stripped = raw.strip()
    if not stripped or not stripped.startswith("<"):
        snippet = stripped[:200] if stripped else "(reponse vide)"
        raise OpenVASError(
            f"OpenVAS/gvmd injoignable ou pas pret via le socket {OPENVAS_SOCKET} - "
            "reponse non-XML recue. Causes probables: conteneur 'openvas' non demarre, "
            "socket gvmd non monte/partage (volume gvmd_socket), "
            "ou feed NVT encore en synchronisation. "
            f"Reponse brute: {snippet}"
        )

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise OpenVASError(
            f"Reponse GMP illisible (XML invalide): {e}. Reponse brute: {stripped[:200]}"
        )

    status = root.get("status", "")
    if status and not status.startswith("2"):
        status_text = root.get("status_text", "erreur inconnue")
        if status == "404" or "config" in status_text.lower():
            raise OpenVASError(
                "OpenVAS: feed NVT probablement pas encore synchronise "
                f"(gvmd: {status_text}). Le 1er sync peut prendre 30-90 min "
                "(voir 'docker logs openvas')."
            )
        raise OpenVASError(f"gvmd a refuse la commande GMP: {status} {status_text}")

    return root

def _map_severity(cvss_score: str) -> str:
    """
    OpenVAS ne fournit nativement que 'High/Medium/Low/Log' (threat), sans
    'critical'. On retombe sur les bandes CVSS du resultat pour rejoindre le
    vocabulaire deja utilise par generate_report() (critical/high/medium/low).
    """
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "low"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"

# ── OPENVAS / GVM — port lists (selecteur de scan) ───────────────────────────
def _get_port_lists():
    """
    Liste live des port lists connues de gvmd (<get_port_lists/>), normalisee en
    [{id, name, count}]. Resolue a chaud expres: les UUID des port lists peuvent
    differer selon la version/le flux GVM, donc on ne les code pas en dur.
    """
    root = _gvm_command("<get_port_lists/>", timeout=15)
    out = []
    for pl in root.findall(".//port_list"):
        pid = pl.get("id")
        if not pid:
            continue
        out.append({
            "id": pid,
            "name": pl.findtext("name") or "",
            "count": pl.findtext("port_count/all") or "?",
        })
    return out

def _resolve_port_list_by_name(name, port_lists=None):
    """UUID d'une port list a partir de son nom (None si absente)."""
    for pl in (port_lists if port_lists is not None else _get_port_lists()):
        if pl["name"] == name:
            return pl["id"]
    return None

# Charset strict pour une plage saisie a la main: chiffres, ',', '-', ':' et les
# prefixes protocole T/U uniquement -> impossible d'injecter <>&" dans le XML
# create_port_list (les cibles passent deja non-echappees, on ne reproduit pas
# ce risque sur une entree de l'admin ici).
_PORT_RANGE_RE = re.compile(r"^[TUtu0-9:,\-\s]+$")

def _normalize_port_range(raw):
    """
    Valide/normalise une plage de ports custom pour create_port_list. Format GMP:
    'T:1-100', 'T:80,443,U:53'... On prefixe 'T:' si aucun protocole n'est donne.
    Leve ValueError si l'entree contient autre chose que des ports/plages.
    """
    s = (raw or "").strip()
    if not s or not _PORT_RANGE_RE.match(s) or not any(c.isdigit() for c in s):
        raise ValueError("Plage de ports invalide (ex attendu: 'T:1-1000' ou '80,443,8080').")
    s = s.upper().replace(" ", "")
    if not (s.startswith("T:") or s.startswith("U:")):
        s = "T:" + s
    return s

def _ensure_port_list(name, port_range):
    """
    UUID de la port list `name`, creee (<create_port_list/>) si absente. Idempotent:
    on verifie d'abord par nom pour ne pas accumuler des doublons a chaque scan.
    `name` est toujours une valeur cote serveur (pas de saisie libre) -> pas besoin
    d'echappement; `port_range` est valide en amont par _normalize_port_range.
    """
    existing = _resolve_port_list_by_name(name)
    if existing:
        return existing
    resp = _gvm_command(
        f"<create_port_list><name>{name}</name>"
        f"<port_range>{port_range}</port_range></create_port_list>",
        timeout=20,
    )
    return resp.get("id")

def _resolve_scan_port_list(port_list_id=None, custom_ports=None):
    """
    Resout l'UUID de port list a utiliser pour un scan, dans l'ordre de priorite:
      1) custom_ports non vide -> port list "Custom: <plage>" creee/reutilisee
      2) port_list_id fourni   -> valide contre la liste live (anti-UUID bidon)
      3) sinon                 -> defaut OPENVAS_DEFAULT_PORT_LIST_NAME (resolu live)
    Renvoie (port_list_id, label_humain). Leve OpenVASError/ValueError au besoin.
    """
    if custom_ports and custom_ports.strip():
        rng = _normalize_port_range(custom_ports)
        return _ensure_port_list(f"Custom: {rng}", rng), f"Custom ({rng})"

    live = _get_port_lists()
    if port_list_id:
        match = next((pl for pl in live if pl["id"] == port_list_id), None)
        if not match:
            # Filet anti-injection: on n'envoie a gvmd qu'un id qu'il connait deja.
            raise OpenVASError("Port list inconnue (id non reconnu par gvmd).")
        return match["id"], match["name"]

    default_id = _resolve_port_list_by_name(OPENVAS_DEFAULT_PORT_LIST_NAME, live)
    return (default_id or OPENVAS_PORT_LIST_ID), OPENVAS_DEFAULT_PORT_LIST_NAME

# ── OPENVAS / GVM — job store (scan asynchrone) ──────────────────────────────
# Un scan OpenVAS "Full and fast" dure de quelques minutes a plusieurs heures:
# bien au-dela de ce qu'un timeout HTTP/proxy raisonnable peut absorber. On
# suit donc le meme principe que le relai ARP Windows (arp_results_cache) :
# la route POST lance un thread de fond et renvoie un job_id immediatement,
# le client poll GET /api/scan/openvas/<job_id> pour suivre l'avancement.
# Limite connue (heritee du meme choix que ACTIVE_TOKENS): en memoire,
# perdu au redemarrage, ne fonctionnerait pas tel quel avec plusieurs workers.
OPENVAS_JOBS = {}
OPENVAS_JOBS_LOCK = threading.Lock()

def _prune_openvas_jobs(max_age: int = 86400):
    """Evite une fuite memoire lente: purge les jobs termines depuis >24h."""
    now = time.time()
    with OPENVAS_JOBS_LOCK:
        stale = [
            jid for jid, j in OPENVAS_JOBS.items()
            if j.get("status") in ("done", "error")
            and now - j.get("finished_at", j.get("started_at", now)) > max_age
        ]
        for jid in stale:
            del OPENVAS_JOBS[jid]

def _openvas_progress_snapshot(report_id: str) -> dict:
    """
    Enrichit le suivi d'un scan EN COURS au-dela du simple % (cf. _openvas_worker):
    lit le rapport partiel via <get_reports> (OpenVAS emet des resultats au fil de
    l'eau) pour exposer la phase, le nombre de resultats live, la repartition par
    severite, la severite max vue, et le dernier NVT/host/port traite (= ce que
    gvmd scanne a l'instant t). Choix GMP:
      - min_qod=0 -> voir les resultats partiels tot (sinon filtres par qualite)
      - rows=20 sort-reverse=created -> charge bornee meme sur un gros rapport,
        et les 20 *derniers* resultats (le plus recent = activite courante)
    Tolerant aux erreurs: tout souci GMP -> {} pour ne JAMAIS casser la boucle de
    poll ni le scan (le suivi enrichi est du bonus, pas un point de defaillance).
    """
    if not report_id:
        return {}
    try:
        root = _gvm_command(
            f'<get_reports report_id="{report_id}" details="1" '
            f'filter="apply_overrides=0 min_qod=0 rows=20 sort-reverse=created"/>',
            timeout=30,
        )
    except OpenVASError:
        return {}
    rep = root.find(".//report/report")
    if rep is None:
        rep = root.find(".//report")
    if rep is None:
        return {}

    rc = rep.find("result_count")
    def _n(tag):
        e = rc.find(tag) if rc is not None else None
        try:
            return int((e.text or "0").strip()) if e is not None and e.text else 0
        except ValueError:
            return 0
    # GVM classe par "threat": hole=High, warning=Medium, info=Low, log=Log. Les
    # comptes par classe sont IMBRIQUES (<log><full>5</full>...</log>), contrairement
    # a <full>/<filtered> qui sont des enfants directs de <result_count> -> on lit
    # bien "<classe>/full" et pas le texte du wrapper (sinon tout ressort a 0).
    sev_counts = {"high": _n("hole/full"), "medium": _n("warning/full"),
                  "low": _n("info/full"), "log": _n("log/full")}

    results = rep.findall(".//results/result")
    # Severite max "vue jusqu'ici", deduite des comptes (autoritatifs) plutot que
    # des seuls 20 derniers resultats; on remonte a 'critical' si un resultat
    # CVSS>=9 figure parmi ceux renvoyes (best-effort, le rapport final tranche).
    highest = None
    if sev_counts["high"]:
        highest = "high"
        for res in results:
            try:
                if float(res.findtext("severity") or 0) >= 9.0:
                    highest = "critical"; break
            except (TypeError, ValueError):
                pass
    elif sev_counts["medium"]:
        highest = "medium"
    elif sev_counts["low"]:
        highest = "low"
    elif sev_counts["log"]:
        highest = "log"

    current = None
    if results:  # sort-reverse=created -> results[0] = le plus recent
        latest = results[0]
        current = {
            "host": latest.findtext("host") or "-",
            "port": latest.findtext("port") or "-",
            "nvt":  (latest.findtext("nvt/name") or "").strip()[:80] or "-",
        }

    return {
        "phase": rep.findtext("scan_run_status") or "",
        "results_total": _n("full"),
        "vuln_count": sev_counts["high"] + sev_counts["medium"] + sev_counts["low"],
        "sev_counts": sev_counts,
        "highest_sev": highest,
        "current": current,
    }

def _openvas_worker(job_id: str, target: str, user: str, port_list_id: str):
    """
    Cree la cible+tache GMP, lance le scan, poll son avancement, puis
    normalise le rapport au format attendu par generate_report() (meme
    schema severity/name/module/port/cve/recommendation que les autres
    modules) afin que ses resultats alimentent le pipeline de reporting
    existant sans modification supplementaire.
    Tourne entierement hors contexte de requete Flask -> audit() recoit
    `user` explicitement (cf. fix de contexte plus haut).
    `port_list_id` est deja resolu/valide par la route (_resolve_scan_port_list).
    """
    def set_state(**kw):
        with OPENVAS_JOBS_LOCK:
            OPENVAS_JOBS[job_id].update(kw)

    suffix = uuid.uuid4().hex[:8]
    try:
        resp = _gvm_command(
            f"<create_target><name>pentoolbox-{suffix}</name><hosts>{target}</hosts>"
            f'<port_list id="{port_list_id}"/></create_target>',
            timeout=30,
        )
        target_id = resp.get("id")

        resp = _gvm_command(
            f'<create_task><name>pentoolbox-{suffix}</name>'
            f'<config id="{OPENVAS_SCAN_CONFIG_ID}"/><target id="{target_id}"/></create_task>',
            timeout=30,
        )
        task_id = resp.get("id")

        resp = _gvm_command(f'<start_task task_id="{task_id}"/>', timeout=30)
        report_id = resp.findtext(".//report_id")

        set_state(status="running", task_id=task_id, report_id=report_id, progress=0)
        audit("OPENVAS_SCAN_STARTED", user=user, details=f"job={job_id} target={target} task={task_id}")

        # Intervalle de poll volontairement large: l'etat d'un scan GVM
        # evolue lentement, interroger gvmd toutes les secondes serait du bruit.
        deadline = time.time() + OPENVAS_MAX_RUNTIME
        t0 = time.time()  # base pour estimer le temps restant (ETA) a partir du %
        status_txt = "Unknown"
        while time.time() < deadline:
            resp = _gvm_command(f'<get_tasks task_id="{task_id}"/>', timeout=30)
            status_txt = resp.findtext(".//status") or "Unknown"
            progress_txt = resp.findtext(".//progress") or "0"
            # gvmd renvoie -1 en fin de scan / quand le % n'a pas de sens -> 0.
            prog = int(progress_txt) if progress_txt.lstrip("-").isdigit() else 0
            if prog < 0:
                prog = 0
            # GVM ne fournit pas d'ETA: on l'estime depuis le % et le temps ecoule
            # (lineaire, donc approximatif - surtout utile passe ~10%).
            eta = int((time.time() - t0) * (100 - prog) / prog) if prog > 0 else None
            # Suivi enrichi (phase, NVT/host courant, comptes par severite live) en
            # lisant le rapport partiel; ne doit jamais faire echouer le scan.
            snap = _openvas_progress_snapshot(report_id)
            set_state(status=status_txt.lower(), progress=prog, eta_seconds=eta, **snap)
            if status_txt in ("Done", "Stopped", "Interrupted"):
                break
            time.sleep(15)
        else:
            raise OpenVASError(
                f"Scan non termine apres {OPENVAS_MAX_RUNTIME}s - arret du suivi "
                "(le scan continue cote gvmd, consultable via la GSA)."
            )

        # Arret demande par l'utilisateur (GMP stop_task) -> etat propre, pas une
        # erreur : la route /api/stop-scan a envoye <stop_task>, gvmd a repondu
        # Stopped/Interrupted. Le frontend gere le statut "stopped" distinctement.
        if status_txt in ("Stopped", "Interrupted"):
            set_state(status="stopped", finished_at=time.time())
            audit("OPENVAS_SCAN_STOPPED", user=user, details=f"job={job_id} target={target} task={task_id}")
            return

        if status_txt != "Done":
            raise OpenVASError(f"Scan termine en etat inattendu: {status_txt}")

        report_root = _gvm_command(f'<get_reports report_id="{report_id}" details="1"/>', timeout=60)
        findings = []
        for result in report_root.findall(".//result"):
            try:
                findings.append({
                    "severity":       _map_severity(result.findtext("severity") or result.findtext(".//nvt/severity")),
                    "name":           result.findtext("name") or "Sans nom",
                    "module":         "OpenVAS",
                    "port":           result.findtext("port") or "-",
                    "cve":            result.findtext(".//nvt/cve") or "-",
                    "recommendation": (result.findtext(".//nvt/solution") or "").strip()[:500],
                })
            except Exception:
                continue  # un resultat malforme ne doit pas faire echouer tout le rapport

        pentoolbox_report_id, _ = _save_scan_report(
            target=target, vulnerabilities=findings, modules_run=["OpenVAS"],
            operator=user, auto=True,
        )
        # cle distincte de report_id (l'UUID gvmd ci-dessus, deja utilise pour
        # get_reports) afin de ne pas confondre les deux identifiants.
        set_state(status="done", findings=findings, pentoolbox_report_id=pentoolbox_report_id, finished_at=time.time())
        audit("OPENVAS_SCAN_DONE", user=user, details=f"job={job_id} target={target} findings={len(findings)}")

    except OpenVASError as e:
        set_state(status="error", error=str(e), finished_at=time.time())
        audit("OPENVAS_SCAN_ERROR", user=user, details=f"job={job_id} target={target} error={e}")
    except Exception as e:
        set_state(status="error", error=f"Erreur interne: {e}", finished_at=time.time())
        audit("OPENVAS_SCAN_ERROR", user=user, details=f"job={job_id} target={target} error={e}")

MSF_JOBS = {}
MSF_JOBS_LOCK = threading.Lock()

# Propriétaire (opérateur) de chaque session Metasploit ouverte VIA PenToolbox
# (exploit MSF ou Hydra->session). Sert l'isolation par utilisateur des sessions
# (BUG 6) : un analyste ne voit/n'interagit qu'avec SES sessions ; l'admin avec
# toutes. Les sessions ouvertes hors PenToolbox (msfconsole directe) n'ont pas de
# propriétaire connu -> visibles de l'admin seulement (repli sûr). En mémoire
# (perdu au redémarrage), comme ACTIVE_TOKENS — cohérent avec un état de session
# live qui n'a de sens que tant que le process tourne.
SESSION_OWNERS = {}
SESSION_OWNERS_LOCK = threading.Lock()

def _record_session_owner(sid, user):
    with SESSION_OWNERS_LOCK:
        SESSION_OWNERS[str(sid)] = user

def _session_owner(sid):
    with SESSION_OWNERS_LOCK:
        return SESSION_OWNERS.get(str(sid))

def _can_access_session(sid, user=None, role=None):
    if role is None:
        role = get_current_role()
    if user is None:
        user = get_current_user()
    if role == "admin":
        return True
    return _session_owner(sid) == user

def _prune_msf_jobs(max_age: int = 86400):
    """Meme logique que _prune_openvas_jobs(): purge les jobs termines depuis >24h."""
    now = time.time()
    with MSF_JOBS_LOCK:
        stale = [
            jid for jid, j in MSF_JOBS.items()
            if j.get("status") in ("done", "error")
            and now - j.get("finished_at", j.get("started_at", now)) > max_age
        ]
        for jid in stale:
            del MSF_JOBS[jid]

def _msf_detect_new_sessions(client, sessions_before: set, target: str):
    """Renvoie [(sid, info), …] des sessions ouvertes PENDANT ce module et
    rattachables à `target`. Le diff avant/après évite de confondre une session
    préexistante avec une nouvelle. Le rattachement à la cible se fait sur les
    champs hôte de la session ; en dernier recours, si une seule session est
    apparue, on la retient (les champs hôte sont parfois vides juste après
    l'ouverture)."""
    try:
        after = client.sessions.list or {}
    except Exception:
        return []
    new_sids = [sid for sid in after.keys() if sid not in sessions_before]
    if not new_sids:
        return []

    def _matches(info):
        for k in ("session_host", "target_host", "tunnel_peer"):
            v = str(info.get(k, "") or "")
            if v and (v == target or v.startswith(target + ":") or target in v):
                return True
        return False

    matched = [(sid, after[sid]) for sid in new_sids if _matches(after[sid])]
    if not matched and len(new_sids) == 1:
        matched = [(new_sids[0], after[new_sids[0]])]
    return matched

def _msf_worker(job_id: str, module: str, target: str, options: dict, user: str):
    """
    Lance un module auxiliary/scanner OU exploit/* via une console RPC
    Metasploit et recupere sa sortie texte, puis sauvegarde un rapport auto
    comme les autres scans (cf. _save_scan_report()). Pour les exploits, le
    payload est fige par MSF_ALLOWED_MODULES[module]["payload"] (jamais
    choisi par l'appelant) et la cible a deja ete verifiee dans
    msf_scan() (ALLOWED_EXPLOIT_SUBNETS) avant le lancement de ce thread.
    Un module se termine en secondes/minutes: pas besoin d'une boucle de
    poll multi-minutes ici - run_module_with_output() de pymetasploit3
    bloque deja jusqu'a completion (ou MSF_MAX_RUNTIME) et renvoie la sortie
    console complete en un seul appel. On tourne quand meme dans un thread
    (comme _openvas_worker) pour ne pas bloquer la requete HTTP, et parce
    que `target`/`module`/`options` viennent d'une requete utilisateur
    potentiellement lente a traiter cote msfrpcd.
    Hors contexte de requete Flask -> audit() recoit `user` explicitement.
    """
    def set_state(**kw):
        with MSF_JOBS_LOCK:
            MSF_JOBS[job_id].update(kw)

    console = None
    try:
        client = _msf_client()
        module_spec = MSF_ALLOWED_MODULES[module]
        # client.modules.use(mtype, mname) prefixe deja mname avec mtype dans
        # run_module_with_output() ("use {moduletype}/{modulename}") - or les
        # cles de MSF_ALLOWED_MODULES incluent deja le prefixe (convention
        # d'affichage standard msfconsole). Sans ce retrait on obtient
        # "use auxiliary/auxiliary/scanner/..." -> module introuvable.
        mtype = "exploit" if module.startswith("exploit/") else "auxiliary"
        mod = client.modules.use(mtype, module.removeprefix(f"{mtype}/"))

        payload_mod = None
        payload_name = module_spec.get("payload")
        if mtype == "exploit" and payload_name:
            payload_mod = client.modules.use("payload", payload_name)
            # Ces 3 exploits n'ont qu'une cible implicite (pas de variantes
            # par OS/version comme les exploits Windows multi-cibles) - on
            # fixe explicitement l'index plutot que de dependre d'un defaut
            # eventuellement non-initialise cote pymetasploit3.
            mod.target = 0

        # RHOSTS/RPORT vont sur le module exploit/auxiliary, LHOST/LPORT (s'il
        # y en a) vont sur le payload — on route sur la base de l'option
        # reellement presente plutot que de coder cette repartition en dur.
        for key, value in options.items():
            if key in mod.options:
                mod[key] = value
            elif payload_mod is not None and key in payload_mod.options:
                payload_mod[key] = value
            # Sinon: cle deja filtree par msf_scan() via module_spec["options"]
            # mais ne correspond a aucune option reelle ici - ignoree plutot
            # que de faire echouer tout le job pour une cle surnumeraire.

        # On photographie les sessions AVANT le lancement : pour un exploit, la
        # sortie console de run_module_with_output() contient parfois la ligne
        # trompeuse "[*] Exploit completed, but no session was created." MEME
        # quand une session a bien ete ouverte (la session s'etablit via un
        # handler/bind, hors du flux console capture). On compare donc l'etat des
        # sessions avant/apres pour dire la verite dans le log (cf. BUG 3).
        sessions_before = set()
        try:
            sessions_before = set((client.sessions.list or {}).keys())
        except Exception:
            pass

        set_state(status="running")
        audit("MSF_SCAN_STARTED", user=user, details=f"job={job_id} target={target} module={module}")

        console = client.consoles.console()
        output = console.run_module_with_output(mod, payload=payload_mod, timeout=MSF_MAX_RUNTIME)

        opened = _msf_detect_new_sessions(client, sessions_before, target) if mtype == "exploit" else []
        for sid, _info in opened:
            _record_session_owner(sid, user)  # isolation par utilisateur (BUG 6)
        if opened:
            # Une session a reellement ete creee -> on neutralise la ligne
            # trompeuse (sans toucher aux logs quand AUCUNE session n'a ete
            # ouverte) et on ajoute un resume clair et actionnable.
            output = output.replace(
                "[*] Exploit completed, but no session was created.",
                "[+] Module termine — session ouverte (voir ci-dessous).")
            summary = "\n".join(
                f"[+] Session ouverte : session #{sid} (type: {info.get('type','shell')}) "
                f"sur {info.get('session_host') or info.get('target_host') or target}"
                for sid, info in opened)
            output = output.rstrip() + "\n" + summary

        # Un exploit ne genere un rapport automatique QUE s'il a reussi (session
        # ouverte). Les auxiliary (version/CVE detection) gardent l'auto-rapport
        # systematique : leur "resultat" est l'information collectee, pas une
        # session (cf. Improvement 3 : pas de rapport vide/d'echec).
        pentoolbox_report_id = None
        if mtype == "exploit" and not opened:
            audit("MSF_SCAN_DONE", user=user, details=f"job={job_id} target={target} module={module} session=none")
        elif _auto_report_enabled("metasploit"):
            session_modules = [f"Session:#{sid}" for sid, _ in opened]
            pentoolbox_report_id, _ = _save_scan_report(
                target=target, scan_output=output,
                modules_run=[f"Metasploit:{module}"] + session_modules,
                operator=user, auto=True,
            )
        set_state(status="done", output=output, pentoolbox_report_id=pentoolbox_report_id,
                  sessions_opened=[{"sid": sid, "type": info.get("type", "shell")} for sid, info in opened],
                  finished_at=time.time())
        audit("MSF_SCAN_DONE", user=user, details=f"job={job_id} target={target} module={module} sessions={len(opened)}")

    except MetasploitError as e:
        set_state(status="error", error=str(e), finished_at=time.time())
        audit("MSF_SCAN_ERROR", user=user, details=f"job={job_id} target={target} error={e}")
    except KeyError as e:
        set_state(status="error", error=f"Option invalide: {e}", finished_at=time.time())
        audit("MSF_SCAN_ERROR", user=user, details=f"job={job_id} target={target} error={e}")
    except Exception as e:
        set_state(status="error", error=f"Erreur interne: {e}", finished_at=time.time())
        audit("MSF_SCAN_ERROR", user=user, details=f"job={job_id} target={target} error={e}")
    finally:
        if console is not None:
            try:
                console.destroy()
            except Exception:
                pass  # le nettoyage de la console RPC ne doit jamais faire echouer le job

def get_current_user():
    try:
        from flask import g
        return getattr(g, "current_user", None) or session.get("user", "unknown")
    except:
        return session.get("user", "unknown")

def get_current_role():
    try:
        from flask import g
        return getattr(g, "current_role", None) or session.get("role", "analyst")
    except:
        return session.get("role", "analyst")

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    try:
        ip   = request.remote_addr
        data = request.json
        if not data:
            return jsonify({"ok": False, "error": "Requete invalide"}), 400

        # Rate limiting
        allowed, msg, remaining = check_rate_limit(ip)
        if not allowed:
            audit("LOGIN_BLOCKED", user=data.get("username","?"), details=f"remaining={remaining}s")
            return jsonify({"ok": False, "error": msg, "retry_after": remaining}), 429

        u = data.get("username", "").strip()
        p = data.get("password", "")

        if check_password(u, p):
            reset_attempts(ip)
            token = secrets.token_hex(32)
            role = get_user_role(u)
            ACTIVE_TOKENS[token] = {"user": u, "role": role}
            session["user"] = u
            session["role"] = role
            session.permanent = True
            audit("LOGIN_OK", user=u, details=f"role={role}")
            resp = jsonify({"ok": True, "user": u, "token": token, "role": role})
            resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            return resp

        record_failed_attempt(ip)
        attempts_left = MAX_ATTEMPTS - LOGIN_ATTEMPTS.get(ip, {}).get("count", 0)
        audit("LOGIN_FAIL", user=u, details=f"attempts_left={max(0,attempts_left)}")
        return jsonify({
            "ok": False,
            "error": f"Identifiants incorrects ({max(0,attempts_left)} tentative(s) restante(s))"
        }), 401

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    try:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            ACTIVE_TOKENS.pop(auth[7:], None)
        audit("LOGOUT", user=get_current_user())
        session.clear()
    except:
        pass
    return jsonify({"ok": True})

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token_data = ACTIVE_TOKENS.get(auth[7:])
            if token_data:
                # Stocke le user/role dans g pour les routes
                from flask import g
                if isinstance(token_data, dict):
                    g.current_user = token_data["user"]
                    g.current_role = token_data["role"]
                else:
                    g.current_user = token_data
                    g.current_role = get_user_role(token_data)
                return f(*args, **kwargs)
        if "user" in session:
            from flask import g
            g.current_user = session["user"]
            g.current_role = session.get("role", get_user_role(session["user"]))
            return f(*args, **kwargs)
        return jsonify({"error": "Non authentifie"}), 401
    return decorated

def require_admin(f):
    """Decorator pour les actions admin uniquement."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import g
        role = getattr(g, "current_role", None) or session.get("role", "analyst")
        if role != "admin":
            audit("UNAUTHORIZED_ADMIN", user=getattr(g, "current_user", "?"))
            return jsonify({"error": "Droits admin requis", "role_required": "admin"}), 403
        return f(*args, **kwargs)
    return decorated



# ── PAGE PRINCIPALE ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ── STATUS ────────────────────────────────────────────────────────────────────
@app.route("/api/status")
@require_auth
def status():
    tools = {t: is_tool_available(t) for t in ["nmap","dig","host","nslookup","curl","hydra","nikto","sqlmap","gvm-cli"]}
    return jsonify({
        "os": platform.system(), "python": platform.python_version(),
        "tools": tools, "reports_count": _count_reports(),
    })

# ── STATISTIQUES TABLEAU DE BORD (persistées, chiffrées, par utilisateur) ─────
# Le tableau de bord (compteurs, graphe d'activité, camembert vulnérabilités,
# activité récente) était purement en mémoire côté client : tout repartait à
# zéro au refresh. On le persiste désormais côté serveur, chiffré (Fernet, même
# mécanisme que les rapports/.users), DANS UN FICHIER PAR INSTALL keyé par
# utilisateur. Choix PAR UTILISATEUR (et non global) : cohérent avec le modèle
# d'isolation des rapports déjà en place (_can_access_report) — chacun voit sa
# propre activité, l'admin n'agrège pas celle des autres. Le nombre de rapports
# reste compté à part (relu du disque via _count_reports), jamais stocké ici.
_DASH_LOCK = threading.Lock()

def _empty_dash_stats():
    return {"stats": {"vulns": 0, "scans": 0, "hosts": 0},
            "vulnData": {"crit": 0, "high": 0, "med": 0, "low": 0},
            "kpis": [], "activity": []}

def _load_all_dash_stats():
    """{username: snapshot} déchiffré (ou {} si absent/illisible)."""
    if not os.path.exists(DASHBOARD_STATS_FILE):
        return {}
    try:
        with open(DASHBOARD_STATS_FILE, "rb") as f:
            return json.loads(FERNET.decrypt(f.read()).decode())
    except Exception:
        return {}

def _save_all_dash_stats(allstats):
    with open(DASHBOARD_STATS_FILE, "wb") as f:
        f.write(FERNET.encrypt(json.dumps(allstats, ensure_ascii=False).encode()))

def _get_dash_stats(user):
    return _load_all_dash_stats().get(user) or _empty_dash_stats()

@app.route("/api/dashboard/stats", methods=["GET"])
@require_auth
def dashboard_stats_get():
    return jsonify(_get_dash_stats(get_current_user()))

@app.route("/api/dashboard/stats", methods=["POST"])
@require_auth
def dashboard_stats_save():
    """Persiste l'instantané du tableau de bord de l'utilisateur courant. Le
    client envoie l'état agrégé (compteurs + KPIs + activité + sévérités) ; on
    le borne pour éviter qu'un client malveillant fasse grossir le fichier."""
    data = request.json or {}
    snap = _empty_dash_stats()
    st = data.get("stats") or {}
    for k in ("vulns", "scans", "hosts"):
        try:
            snap["stats"][k] = max(0, int(st.get(k, 0)))
        except (TypeError, ValueError):
            snap["stats"][k] = 0
    vd = data.get("vulnData") or {}
    for k in ("crit", "high", "med", "low"):
        try:
            snap["vulnData"][k] = max(0, int(vd.get(k, 0)))
        except (TypeError, ValueError):
            snap["vulnData"][k] = 0
    if isinstance(data.get("kpis"), list):
        snap["kpis"] = data["kpis"][:20]
    if isinstance(data.get("activity"), list):
        snap["activity"] = data["activity"][:10]
    user = get_current_user()
    with _DASH_LOCK:
        allstats = _load_all_dash_stats()
        allstats[user] = snap
        _save_all_dash_stats(allstats)
    return jsonify({"ok": True})

@app.route("/api/dashboard/stats", methods=["DELETE"])
@require_auth
def dashboard_stats_clear():
    user = get_current_user()
    with _DASH_LOCK:
        allstats = _load_all_dash_stats()
        if user in allstats:
            del allstats[user]
            _save_all_dash_stats(allstats)
    audit("DASHBOARD_STATS_CLEARED", details=f"user={user}")
    return jsonify({"ok": True})

def _iter_reports():
    """Itère sur (fname, report_dict) pour chaque rapport déchiffrable de
    REPORTS_DIR (ignore les fichiers transitoires/non-rapports et ceux qui ne
    se déchiffrent pas)."""
    try:
        names = os.listdir(REPORTS_DIR)
    except OSError:
        return
    for fname in names:
        if not fname.endswith(".enc"):
            continue
        try:
            with open(os.path.join(REPORTS_DIR, fname), "rb") as f:
                yield fname, decrypt_report(f.read())
        except Exception:
            continue

def _can_access_report(report, user=None, role=None):
    """Isolation par utilisateur : un rapport appartient à son `operator`.
    L'admin voit et agit sur tous les rapports ; un analyste uniquement les
    siens. On filtre sur le champ `operator` déjà présent dans chaque rapport
    (pas de préfixe de nom de fichier ni de migration) — le cas « admin voit
    tout » en découle naturellement."""
    if role is None:
        role = get_current_role()
    if user is None:
        user = get_current_user()
    if role == "admin":
        return True
    return report.get("operator") == user

def _count_reports(user=None, role=None):
    """Nombre de rapports VISIBLES par l'utilisateur courant (rapports dont il
    est l'`operator`, ou tous si admin). Compté en relisant le disque, jamais un
    état en mémoire."""
    n = 0
    for _, r in _iter_reports():
        if _can_access_report(r, user, role):
            n += 1
    return n

def _tool_version(cmd, timeout=3):
    """1re ligne pertinente de la sortie d'une commande de version (best-effort)."""
    try:
        out = run_cmd(cmd, timeout=timeout)
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line[:70]
    except Exception:
        pass
    return ""

@app.route("/api/tools/status")
@require_auth
def tools_status():
    """État réel et détaillé de la chaîne d'outils, regroupé par catégorie.
    Contrairement à /api/status (présence de binaire local uniquement), cette
    route SONDE la joignabilité des outils-services (OpenVAS/gvmd et Metasploit
    tournent dans des conteneurs distincts : leur binaire local ne dit rien de
    leur disponibilité) et liste les ressources (wordlists). Statuts possibles :
    'ok' (vert), 'unreachable' (orange : installé mais service injoignable),
    'absent' (rouge)."""
    scanners = []
    for tid, label, vcmd in [
        ("nmap",   "Nmap",   "nmap --version"),
        ("nikto",  "Nikto",  "nikto -Version"),
        ("sqlmap", "SQLMap", "sqlmap --version"),
        ("hydra",  "Hydra",  "hydra -h"),
        ("john",   "John the Ripper", "john --list=build-info"),
    ]:
        present = is_tool_available(tid)
        scanners.append({"id": tid, "label": label, "status": "ok" if present else "absent",
                         "detail": (_tool_version(vcmd) or "installé") if present else "non installé"})

    netg = []
    _dig_ok = is_tool_available("dig"); _nsl_ok = is_tool_available("nslookup")
    netg.append({"id": "dns-lookup", "label": "DNS Lookup (dig/nslookup)",
                 "status": "ok" if (_dig_ok or _nsl_ok) else "absent",
                 "detail": ((", ".join(b for b, ok in (("dig", _dig_ok), ("nslookup", _nsl_ok)) if ok) + " disponible")
                            if (_dig_ok or _nsl_ok) else "dig & nslookup absents (repli Python socket, enreg. A uniquement)")})
    for tid, label in [("dig", "dig"), ("host", "host"), ("nslookup", "nslookup"),
                       ("curl", "curl"), ("smbclient", "smbclient"), ("enum4linux-ng", "enum4linux-ng"),
                       ("dnsrecon", "dnsrecon (recon passive)")]:
        present = is_tool_available(tid)
        netg.append({"id": tid, "label": label, "status": "ok" if present else "absent",
                     "detail": "installé" if present else "non installé"})

    services = []
    try:
        root = _gvm_command("<get_version/>", timeout=8)
        gver = root.findtext(".//version") or ""
        services.append({"id": "openvas", "label": "OpenVAS / gvmd", "status": "ok",
                         "detail": f"gvmd joignable{(' (GMP ' + gver + ')') if gver else ''}"})
    except Exception:
        bin_ok = is_tool_available("gvm-cli")
        services.append({"id": "openvas", "label": "OpenVAS / gvmd",
                         "status": "unreachable" if bin_ok else "absent",
                         "detail": "gvm-cli présent, gvmd injoignable (conteneur 'openvas' / feed NVT)" if bin_ok else "gvm-cli absent"})
    try:
        _msf_probe(timeout=6)
        services.append({"id": "metasploit", "label": "Metasploit RPC", "status": "ok",
                         "detail": f"msfrpcd joignable ({MSF_RPC_HOST}:{MSF_RPC_PORT})"})
    except Exception:
        services.append({"id": "metasploit", "label": "Metasploit RPC", "status": "unreachable",
                         "detail": f"msfrpcd injoignable ({MSF_RPC_HOST}:{MSF_RPC_PORT}) — conteneur 'metasploit'"})

    resources = []
    for entry in HYDRA_WORDLIST_FILES:
        path = _resolve_wordlist_file(entry["id"])
        resources.append({"id": entry["id"], "label": entry["label"],
                          "status": "ok" if path else "absent",
                          "detail": path if path else "absente"})

    return jsonify({
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "docker": bool(os.environ.get("DOCKER_ENV")),
        "groups": [
            {"name": "Scanners",      "tools": scanners},
            {"name": "Réseau / DNS",  "tools": netg},
            {"name": "Services",      "tools": services},
            {"name": "Wordlists",     "tools": resources},
        ],
    })

# ── SUGGESTIONS D'EXPLOITATION ──────────────────────────────────────────────────
# Analyse heuristique (pas de scan reel ici) des resultats d'un scan deja execute
# pour proposer des modules a essayer ensuite (Hydra/SQLMap/Nikto/OpenVAS/MSF).
# Volontairement low-tech: regex sur le texte de sortie, pas d'IA — sert de
# raccourci de navigation ("port 22 ouvert -> bouton vers Hydra prerempli"),
# pas de detection de vulnerabilite. La vraie detection reste OpenVAS/Nikto/MSF.
_PORT_SUGGESTIONS = [
    # (regex sur la sortie du scan, page cible, libelle, motif)
    (re.compile(r"\b22/tcp\s+open\s+ssh\b", re.I), "hydra", "Bruteforce SSH", "Port 22/SSH ouvert"),
    (re.compile(r"\b21/tcp\s+open\s+ftp\b", re.I), "hydra", "Bruteforce FTP", "Port 21/FTP ouvert"),
    (re.compile(r"\b3389/tcp\s+open\s+ms-wbt-server\b", re.I), "hydra", "Bruteforce RDP", "Port 3389/RDP ouvert"),
    (re.compile(r"\b445/tcp\s+open\s+microsoft-ds\b", re.I), "hydra", "Bruteforce SMB", "Port 445/SMB ouvert"),
    (re.compile(r"\b3306/tcp\s+open\s+mysql\b", re.I), "sqlmap", "Test d'injection MySQL", "Port 3306/MySQL ouvert"),
    (re.compile(r"\b(80|443|8080|8443)/tcp\s+open\s+(http|https|ssl/http)\b", re.I), "nikto", "Audit du service web", "Port web ouvert"),
]


def analyze_and_propose_exploit(scan_results: str, scan_type: str) -> list[dict]:
    """Propose des modules a tester ensuite a partir du texte d'un scan deja lance."""
    if not scan_results:
        return []
    suggestions = []
    if scan_type == "nmap":
        for pattern, page, name, reason in _PORT_SUGGESTIONS:
            if pattern.search(scan_results):
                suggestions.append({"page": page, "name": name, "reason": reason})
    elif scan_type == "nikto":
        if re.search(r"\bsql\b.*inject|injection.*\bsql\b", scan_results, re.I):
            suggestions.append({"page": "sqlmap", "name": "Test d'injection SQL", "reason": "Indice SQLi dans la sortie Nikto"})
        if re.search(r"\bxss\b|cross.site.scripting", scan_results, re.I):
            suggestions.append({"page": None, "name": "Vérification XSS manuelle", "reason": "Indice XSS dans la sortie Nikto"})
    # dedup en gardant l'ordre (meme page+name ne doit apparaitre qu'une fois)
    seen = set()
    deduped = []
    for s in suggestions:
        key = (s["page"], s["name"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped


@app.route("/api/exploit/suggest", methods=["POST"])
@require_auth
def suggest_exploit():
    data = request.json or {}
    scan_type = data.get("scan_type", "")
    results = data.get("results", "")
    suggestions = analyze_and_propose_exploit(results, scan_type)
    audit("SUGGEST_EXPLOIT", details=f"scan_type={scan_type} count={len(suggestions)}")
    return jsonify({"ok": True, "suggestions": suggestions})


# ── EXPLOITATION AUTOMATISEE (multi-modules, scans nmap NSE reels) ────────────
# La page "Exploitation automatisee" lance, pour chaque service coche, un vrai
# scan nmap NSE cible (detection de vulnerabilites), puis normalise la sortie
# XML en findings au meme schema que generate_report()
# (severity/name/module/port/cve/recommendation) pour alimenter le tableau, les
# graphes et le pipeline de rapport existants.
#
# Ce sont des scripts de DETECTION (categories vuln/safe/default), pas des
# exploits accordant un shell distant: comme les modules auxiliary/scanner cote
# Metasploit, ils ne sont donc PAS restreints aux sous-reseaux de labo. La vraie
# exploitation (shell distant) reste la page Metasploit, scope-gatee par
# ALLOWED_EXPLOIT_SUBNETS. La cible passe par _is_safe_scan_target() (meme
# garde-fou anti-injection que les scans nmap eleves) avant toute interpolation
# dans la commande shell.
# Jeux de scripts NSE enrichis par protocole (IMPROVEMENT 4). Chaque script est
# de la DÉTECTION (pas du bruteforce — cf. retrait de ftp-brute) et passe par le
# même pipeline _parse_nmap_exploit_xml() -> schéma de findings. Les scripts
# absents de l'hôte sont signalés available:false par /api/exploit/modules.
EXPLOIT_MODULES = {
    "http":  {"label": "HTTP/HTTPS", "ports": "80,443,8080,8443",
              # http-git: .git exposé ; http-shellshock: CVE-2014-6271 ;
              # http-default-accounts: creds par défaut ; http-headers: divulgation
              # de version serveur ; http-enum: énumération de répertoires.
              "scripts": "http-enum,http-headers,http-methods,http-git,http-shellshock,http-default-accounts,http-csrf,http-sql-injection"},
    "smb":   {"label": "SMB", "ports": "445",
              # smb2-security-mode: signature SMBv2 ; smb-os-discovery: OS ;
              # smb-enum-shares: partages ; smb-vuln-ms17-010 (EternalBlue) /
              # ms08-067. (Énumération approfondie SMB: page dédiée enum4linux-ng.)
              "scripts": "smb-protocols,smb-security-mode,smb2-security-mode,smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010,smb-vuln-ms08-067"},
    "ftp":   {"label": "FTP", "ports": "21",
              # ftp-anon: login anonyme ; ftp-syst/ftp-bounce: bannière & bounce.
              # ftp-brute (bruteforce de creds) retire: c'est de l'attaque, pas
              # de la detection comme les autres modules — et il depasse le
              # proxy_read_timeout nginx (>100s), d'ou un 504. Le bruteforce FTP
              # reste disponible sur la page dediee Hydra (/api/hydra).
              "scripts": "ftp-anon,ftp-syst,ftp-bounce"},
    "ssh":   {"label": "SSH", "ports": "22",
              # ssh2-enum-algos: KEX/chiffrements faibles ; ssh-hostkey: clés ;
              # ssh-auth-methods: méthodes d'auth ; sshv1: protocole v1 obsolète.
              "scripts": "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1"},
    "mysql": {"label": "MySQL", "ports": "3306",
              # mysql-empty-password: root sans mot de passe ; mysql-vuln-
              # cve2012-2122: bypass d'auth ; mysql-info: version.
              "scripts": "mysql-info,mysql-empty-password,mysql-vuln-cve2012-2122,mysql-databases,mysql-users"},
    "rdp":   {"label": "RDP", "ports": "3389",
              # rdp-enum-encryption: niveau de chiffrement & exigence NLA ;
              # ssl-cert: inspection du certificat ; rdp-vuln-ms12-020. (Pas de
              # NSE BlueKeep officiel -> détection BlueKeep via Metasploit.)
              "scripts": "rdp-ntlm-info,rdp-enum-encryption,ssl-cert,rdp-vuln-ms12-020"},
}

# Severite + recommandation pour les scripts de la librairie "vulns" de nmap
# (ceux qui emettent un bloc "State: VULNERABLE"). Defaut: severite deduite du
# "Risk factor" du script, sinon "high".
_VULN_META = {
    "smb-vuln-ms17-010":     ("critical", "Appliquer le correctif MS17-010, desactiver SMBv1"),
    "rdp-vuln-ms12-020":     ("critical", "Appliquer le correctif MS12-020 (RDP), activer NLA, restreindre 3389"),
    "ftp-vsftpd-backdoor":   ("critical", "Mettre a jour vsftpd (backdoor de la 2.3.4)"),
    "ftp-proftpd-backdoor":  ("critical", "Mettre a jour ProFTPD (mod_copy / backdoor)"),
}

# Detecteurs cibles pour les scripts info/enum (qui n'utilisent pas la librairie
# vulns): script_id -> (regex declencheur, severite, nom, recommandation). On
# n'inscrit un finding que si le script a reellement signale la condition.
_NSE_SIGNALS = {
    "ftp-anon":             (re.compile(r"Anonymous FTP login allowed", re.I), "high",
                             "Acces FTP anonyme autorise", "Desactiver le login anonyme sur le service FTP"),
    "mysql-empty-password": (re.compile(r"has empty password", re.I), "critical",
                             "Compte MySQL sans mot de passe", "Definir un mot de passe pour tous les comptes MySQL"),
    # NB: ces scripts impriment "Couldn't find any ... vulnerabilities" quand
    # ils ne trouvent rien -> on ancre sur la formulation POSITIVE explicite
    # ("Possible sqli" / "Found the following ...") pour eviter le faux positif.
    "http-sql-injection":   (re.compile(r"Possible sqli", re.I), "critical",
                             "Injection SQL possible (HTTP)", "Requetes preparees / ORM, valider les entrees"),
    "http-stored-xss":      (re.compile(r"Found the following stored XSS", re.I), "high",
                             "XSS stocke possible", "Encoder les sorties HTML, Content-Security-Policy"),
    "http-csrf":            (re.compile(r"Found the following possible CSRF", re.I), "medium",
                             "CSRF possible", "Jetons anti-CSRF sur les formulaires sensibles"),
    "sshv1":                (re.compile(r"\bSSHv1\b|supports SSH protocol 1", re.I), "high",
                             "SSHv1 supporte (protocole obsolete)", "Desactiver SSHv1, n'autoriser que SSHv2"),
    "smb-protocols":        (re.compile(r"SMBv1", re.I), "medium",
                             "SMBv1 active (obsolete/dangereux)", "Desactiver SMBv1, n'autoriser que SMBv2/3"),
    # ── Détecteurs ajoutés (IMPROVEMENT 4) ───────────────────────────────────
    "ssh2-enum-algos":      (re.compile(r"arcfour|-cbc\b|diffie-hellman-group1-sha1|ssh-dss|hmac-md5", re.I), "medium",
                             "Algorithmes SSH faibles proposes", "Desactiver les algos obsoletes (CBC, arcfour, DH group1, DSA, HMAC-MD5)"),
    "http-git":             (re.compile(r"Git repository found|\.git/|repository found", re.I), "high",
                             "Depot .git expose", "Bloquer l'acces a .git/ cote serveur web"),
    "http-default-accounts":(re.compile(r"Possible default|valid credentials|default account", re.I), "critical",
                             "Comptes par defaut detectes (HTTP)", "Changer immediatement les identifiants par defaut"),
    "smb-security-mode":    (re.compile(r"message_signing:\s*disabled|enabled but not required|signing.{0,30}(disabled|not required)", re.I), "medium",
                             "Signature SMB non requise", "Exiger la signature SMB (relais NTLM possible sinon)"),
    "smb2-security-mode":   (re.compile(r"not required|disabled", re.I), "medium",
                             "Signature SMBv2 non requise", "Exiger la signature SMBv2 (relais NTLM possible sinon)"),
}

def _exploit_finding(severity, name, module_label, port, cve, recommendation):
    return {"severity": severity, "name": name, "module": module_label,
            "port": port, "cve": cve or "-", "recommendation": recommendation}

def _parse_nmap_exploit_xml(xml_text: str, module: str):
    """
    Parse la sortie XML d'un `nmap --script ...` en liste de findings. Retourne
    None si la sortie n'est pas du XML exploitable (nmap a echoue avant de
    produire un rapport) pour que l'appelant puisse remonter l'erreur brute.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    label = EXPLOIT_MODULES[module]["label"]
    findings = []

    def _scan_script(sid, out, portid):
        # 1) Scripts "vulns": bloc structure "State: VULNERABLE".
        if re.search(r"State:\s*(?:LIKELY )?VULNERABLE", out):
            cve = re.search(r"(CVE-\d{4}-\d+)", out)
            title_m = re.search(r"\n\s*VULNERABLE:\s*\n\s*([^\n]+)", out)
            title = (title_m.group(1).strip() if title_m else sid)[:140]
            sev, reco = _VULN_META.get(sid, (None, None))
            if sev is None:
                rf = re.search(r"Risk factor:\s*(\w+)", out, re.I)
                sev = rf.group(1).lower() if rf and rf.group(1).lower() in (
                    "critical", "high", "medium", "low") else "high"
                reco = "Corriger la vulnerabilite signalee (cf. detail du scan)"
            findings.append(_exploit_finding(sev, title, label, portid,
                                             cve.group(1) if cve else "-", reco))
            return
        # 2) Detecteurs info/enum cibles.
        sig = _NSE_SIGNALS.get(sid)
        if sig and sig[0].search(out):
            _, sev, name, reco = sig
            cve = re.search(r"(CVE-\d{4}-\d+)", out)
            findings.append(_exploit_finding(sev, name, label, portid,
                                             cve.group(1) if cve else "-", reco))
            return
        # 3) http-methods: methodes potentiellement dangereuses.
        if sid == "http-methods":
            risky = re.search(r"Potentially risky methods:\s*([^\n]+)", out)
            if risky:
                findings.append(_exploit_finding(
                    "low", "Methodes HTTP risquees: " + risky.group(1).strip(),
                    label, portid, "-",
                    "Desactiver les methodes HTTP inutiles (PUT/DELETE/TRACE)"))

    # Port par defaut du module pour les scripts sans portid (scripts d'hote).
    default_port = EXPLOIT_MODULES[module]["ports"].split(",")[0].strip() or "-"
    for host in root.findall(".//host"):
        # Scripts attaches a un port (http-*, ftp-*, ssh-*, mysql-*, rdp-enum-*...).
        for port in host.findall(".//port"):
            portid = port.get("portid", "-")
            for script in port.findall("script"):
                _scan_script(script.get("id", ""), script.get("output", "") or "", portid)
        # Scripts d'HOTE (<hostscript>) : smb-protocols, smb-security-mode,
        # smb-vuln-ms17-010, rdp-vuln-ms12-020... nmap les rattache a l'hote, PAS
        # a un <port>. Sans ce parcours, leurs findings (SMBv1, MS17-010, MS12-020)
        # etaient silencieusement perdus et le module SMB/RDP renvoyait toujours 0.
        for hs in host.findall("hostscript"):
            for script in hs.findall("script"):
                _scan_script(script.get("id", ""), script.get("output", "") or "", default_port)
    return findings

def _summarize_nmap_xml(xml_text: str, label: str):
    """Resume lisible (ports ouverts + service) pour le terminal de l'UI."""
    lines = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return lines
    if not root.findall(".//host"):
        lines.append(f"[~] {label}: hote injoignable ou aucun resultat")
        return lines
    open_any = False
    for host in root.findall(".//host"):
        for port in host.findall(".//port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            open_any = True
            svc = port.find("service")
            name = svc.get("name", "?") if svc is not None else "?"
            extra = ""
            if svc is not None:
                extra = (" " + (svc.get("product", "") + " " + svc.get("version", "")).strip()).rstrip()
            lines.append(f"[+] {port.get('portid')}/{port.get('protocol', 'tcp')} open {name}{extra}")
    if not open_any:
        lines.append(f"[*] {label}: aucun port ouvert sur la plage testee")
    return lines

# ── DISPONIBILITE DES SCRIPTS NSE ────────────────────────────────────────────
# Un module exploit/* ne doit etre propose dans l'UI que si les scripts NSE
# qu'il invoque existent reellement sur ce systeme: sinon `nmap --script X`
# echoue en bloc ("'X' did not match a category, filename, or directory") et le
# module parait casse. On localise le repertoire des scripts nmap puis on
# verifie la presence de chaque .nse. Mis en cache (le contenu ne bouge pas en
# cours d'execution).
_NSE_DIR_CACHE = {"scanned": False, "dir": None}

def _nse_scripts_dir():
    if _NSE_DIR_CACHE["scanned"]:
        return _NSE_DIR_CACHE["dir"]
    candidates = [
        "/usr/share/nmap/scripts", "/usr/local/share/nmap/scripts",
        "/opt/homebrew/share/nmap/scripts", "/opt/local/share/nmap/scripts",
        r"C:\Program Files (x86)\Nmap\scripts", r"C:\Program Files\Nmap\scripts",
    ]
    found = next((d for d in candidates if os.path.isdir(d)), None)
    _NSE_DIR_CACHE.update(scanned=True, dir=found)
    return found

def _nse_available(script: str) -> bool:
    d = _nse_scripts_dir()
    return bool(d) and os.path.isfile(os.path.join(d, script + ".nse"))

def _module_script_status(module: str):
    """(scripts_presents, scripts_manquants) pour un module exploit donne."""
    scripts = [s.strip() for s in EXPLOIT_MODULES[module]["scripts"].split(",") if s.strip()]
    present = [s for s in scripts if _nse_available(s)]
    missing = [s for s in scripts if not _nse_available(s)]
    return present, missing

def _module_availability(module: str):
    """
    (available, scripts_a_lancer, manquants). Si le repertoire NSE est
    introuvable, on ne peut pas *confirmer* l'absence -> on n'invalide pas le
    module (available=True, on laisse nmap trancher avec sa liste complete).
    Sinon le module est disponible des qu'au moins un de ses scripts est present;
    on ne lancera que les scripts reellement presents.
    """
    if _nse_scripts_dir() is None:
        scripts = [s.strip() for s in EXPLOIT_MODULES[module]["scripts"].split(",") if s.strip()]
        return True, scripts, []
    present, missing = _module_script_status(module)
    return (len(present) > 0), present, missing

@app.route("/api/exploit/modules")
@require_auth
def exploit_modules():
    """
    Etat de disponibilite de chaque module pour l'UI: le frontend desactive
    (avec un motif "script NSE manquant") les services dont aucun script n'est
    present, plutot que de proposer un module qui echouerait cote nmap.
    """
    out = {}
    for m, spec in EXPLOIT_MODULES.items():
        available, _present, missing = _module_availability(m)
        out[m] = {"label": spec["label"], "ports": spec["ports"],
                  "available": available, "missing": missing}
    return jsonify(out)

@app.route("/api/exploit/run", methods=["POST"])
@require_auth
def exploit_run():
    """Lance multi-modules, retourne log texte + vulnerabilites."""
    data    = request.json or {}
    target  = data.get("target", "").strip()
    modules = data.get("modules") or []
    if not target:
        return jsonify({"error": "Cible requise"}), 400
    if not isinstance(modules, list) or not modules:
        return jsonify({"error": "Selectionnez au moins un module"}), 400
    modules = [m for m in modules if m in EXPLOIT_MODULES]
    if not modules:
        return jsonify({"error": "Aucun module valide selectionne"}), 400
    if not is_tool_available("nmap"):
        return jsonify({"error": "Nmap non installe", "install": "sudo apt install nmap"}), 400
    if not _is_safe_scan_target(target):
        return jsonify({"error": "Cible invalide (caracteres non autorises)"}), 400

    audit("EXPLOIT_RUN", details=f"target={target} modules={','.join(modules)}")
    log = [f"[*] Exploitation -> {target}", f"[*] Modules: {', '.join(modules)}", "=" * 50]
    vulns = []
    for m in modules:
        try:
            spec = EXPLOIT_MODULES[m]
            available, scripts, missing = _module_availability(m)
            if not available:
                log.append(f"[!] {spec['label']}: non disponible - script(s) NSE manquant(s): {', '.join(missing)}")
                log.append("-" * 40)
                continue
            if missing:
                log.append(f"[~] {spec['label']}: script(s) absent(s) ignore(s): {', '.join(missing)}")
            log.append(f"[*] Module {spec['label']} (ports {spec['ports']}) -> {target}")
            cmd = f"nmap -Pn -sV -p {spec['ports']} --script {','.join(scripts)} -oX - {target}"
            raw = run_cmd(cmd, timeout=180)
            if raw.startswith("[!] Timeout"):
                log.append(f"[~] {spec['label']}: timeout (180s) - module ignore")
                log.append("-" * 40)
                continue
            parsed = _parse_nmap_exploit_xml(raw, m)
            if parsed is None:
                error_text = raw.strip()[:300]
                log.append(f"[!] {spec['label']}: echec nmap - {error_text[:100]}")
                log.append("-" * 40)
                continue
            log.extend(_summarize_nmap_xml(raw, spec["label"]))
            if parsed:
                for f in parsed:
                    log.append(f"[!] {f['severity'].upper()}: {f['name']} ({f['cve']})")
                vulns.extend(parsed)
            else:
                log.append(f"[✓] {spec['label']}: aucune vulnerabilite detectee")
            log.append("-" * 40)
        except Exception as e:
            log.append(f"[!] {m}: Erreur - {str(e)[:80]}")
            log.append("-" * 40)
    log.append("=" * 50)
    log.append(f"[*] {len(vulns)} vulnerabilite(s) detectee(s)")
    audit("EXPLOIT_DONE", details=f"target={target} vulns={len(vulns)}")
    return jsonify({"ok": True, "target": target, "modules_run": modules,
                    "output": "\n".join(log), "vulnerabilities": vulns})

@app.route("/api/settings/auto-report", methods=["GET"])
@require_auth
def get_auto_report_prefs():
    """Préférences d'auto-rapport par outil (toggle, défaut activé). Accessible à
    tout utilisateur authentifié : ça pilote SES propres scans (réglage global du
    poste, pas une action admin)."""
    prefs = get_setting("auto_report", {}) or {}
    return jsonify({"auto_report": {t: bool(prefs.get(t, True)) for t in AUTO_REPORT_TOOLS},
                    "tools": AUTO_REPORT_TOOLS})

@app.route("/api/settings/auto-report", methods=["PUT"])
@require_auth
def update_auto_report_prefs():
    data = request.json or {}
    incoming = data.get("auto_report")
    if not isinstance(incoming, dict):
        return jsonify({"error": "Champ auto_report (objet) requis"}), 400
    prefs = get_setting("auto_report", {}) or {}
    for t in AUTO_REPORT_TOOLS:
        if t in incoming:
            prefs[t] = bool(incoming[t])
    try:
        set_setting("auto_report", prefs)
    except OSError as e:
        return jsonify({"error": f"Écriture de la configuration impossible : {e}"}), 500
    audit("SETTINGS_AUTOREPORT_UPDATED", details=f"prefs={prefs}")
    return jsonify({"ok": True, "auto_report": {t: bool(prefs.get(t, True)) for t in AUTO_REPORT_TOOLS}})

@app.route("/api/settings/subnets", methods=["GET"])
@require_auth
@require_admin
def get_allowed_exploit_subnets():
    """Valeur actuelle (base si presente, sinon variable d'env) pour que l'UI admin puisse l'afficher avant modification."""
    return jsonify({"allowed_exploit_subnets": _allowed_exploit_subnets_raw()})

@app.route("/api/settings/subnets", methods=["PUT"])
@require_auth
@require_admin
def update_allowed_exploit_subnets():
    """
    Modifie a chaud la liste des sous-reseaux CIDR autorises pour les modules
    exploit/* (cf. ALLOWED_EXPLOIT_SUBNETS / _target_in_allowed_exploit_subnets()
    / msf_scan()) - evite de redemarrer le conteneur a chaque changement de
    labo. La valeur soumise est validee (ipaddress.ip_network) avant d'etre
    persistee dans .settings.json: une entree malformee ne doit jamais finir
    en base et bloquer silencieusement tous les exploits par la suite.
    """
    data = request.json or {}
    raw = data.get("subnets", "")
    if not isinstance(raw, str):
        return jsonify({"error": "Le champ subnets doit etre une chaine CSV de CIDR"}), 400

    entries = [s.strip() for s in raw.split(",") if s.strip()]
    invalid = []
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            invalid.append(entry)
    if invalid:
        return jsonify({"error": f"CIDR invalide(s): {', '.join(invalid)}"}), 400

    # La persistance peut echouer (permissions sur config/, disque plein...).
    # On renvoie alors une ERREUR JSON explicite plutot que de laisser
    # l'exception remonter en page HTML 500 - sinon le frontend fait
    # res.json() sur du HTML et affiche "JSON.parse: unexpected character".
    try:
        set_setting("allowed_exploit_subnets", raw)
    except OSError as e:
        audit("SETTINGS_SUBNETS_WRITE_ERROR", details=f"error={e}")
        return jsonify({
            "error": f"Impossible d'ecrire la configuration ({SETTINGS_FILE}): {e}. "
                     "Verifiez les permissions du dossier config/."
        }), 500
    audit("SETTINGS_SUBNETS_UPDATED", details=f"subnets={raw}")
    return jsonify({"ok": True, "allowed_exploit_subnets": entries})

# ── GESTION UTILISATEURS (admin seulement) ────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@require_auth
@require_admin
def list_users():
    users = load_users()
    user_list = []
    for u, v in users.items():
        role = v["role"] if isinstance(v, dict) else ("admin" if u == "admin" else "analyst")
        user_list.append({"username": u, "role": role})
    return jsonify({"users": user_list})

@app.route("/api/users", methods=["POST"])
@require_auth
@require_admin
def create_user():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"ok": False, "error": "Username et password requis"}), 400
    if len(username) < 3:
        return jsonify({"ok": False, "error": "Username trop court (min 3 chars)"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Mot de passe trop court (min 6 chars)"}), 400
    users = load_users()
    if username in users:
        return jsonify({"ok": False, "error": "Utilisateur existe deja"}), 409
    role = request.json.get("role", "analyst")
    if role not in ["admin", "analyst"]:
        role = "analyst"
    users[username] = {"hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), "role": role}
    save_users(users)
    audit("USER_CREATED", details=f"new_user={username} role={role}")
    return jsonify({"ok": True, "message": f"Utilisateur {username} cree"})

@app.route("/api/users/<username>", methods=["DELETE"])
@require_auth
@require_admin
def delete_user(username):
    if username == "admin":
        return jsonify({"ok": False, "error": "Impossible de supprimer admin"}), 400
    # Un admin ne peut pas supprimer son PROPRE compte (éviter de se verrouiller
    # dehors / de perdre la session en cours) — il doit le faire via un autre admin.
    if username == get_current_user():
        return jsonify({"ok": False, "error": "Impossible de supprimer votre propre compte"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "Utilisateur introuvable"}), 404
    del users[username]
    save_users(users)
    # Invalide les tokens de cet utilisateur
    for token, user in list(ACTIVE_TOKENS.items()):
        if user == username:
            del ACTIVE_TOKENS[token]
    audit("USER_DELETED", details=f"deleted_user={username}")
    return jsonify({"ok": True, "message": f"Utilisateur {username} supprime"})

@app.route("/api/users/<username>/password", methods=["PUT"])
@require_auth
def change_password(username):
    current_user = get_current_user()
    current_role = get_current_role()
    # Protection spéciale : le mot de passe du compte admin par défaut (bootstrap)
    # ne peut être modifié QUE par lui-même — jamais par un autre administrateur.
    if username == "admin" and current_user != "admin":
        return jsonify({"ok": False, "error": "Seul l'admin par défaut peut modifier son propre mot de passe"}), 403
    # Sinon : un administrateur (par rôle) peut changer le mdp de n'importe quel
    # compte ; un non-admin uniquement le sien.
    if current_role != "admin" and current_user != username:
        return jsonify({"ok": False, "error": "Non autorise"}), 403
    data = request.json
    new_password = data.get("password", "")
    if len(new_password) < 6:
        return jsonify({"ok": False, "error": "Mot de passe trop court (min 6 chars)"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "Utilisateur introuvable"}), 404
    existing = users[username]
    role = existing["role"] if isinstance(existing, dict) else ("admin" if username == "admin" else "analyst")
    users[username] = {"hash": bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode(), "role": role}
    save_users(users)
    audit("PASSWORD_CHANGED", details=f"target_user={username}")
    return jsonify({"ok": True, "message": "Mot de passe modifie"})

# ── AUDIT LOG ─────────────────────────────────────────────────────────────────
@app.route("/api/audit")
@require_auth
@require_admin
def get_audit_log():
    # audit.log est chiffré at-rest (log_encrypted) -> on RENVOIE le clair via
    # read_encrypted_logs(), sinon l'UI affichait les jetons Fernet bruts
    # (gAAAAAB…), donnant l'impression de logs "corrompus/illisibles".
    return jsonify({"lines": read_encrypted_logs(200)})

# ── DNS DUMPSTER ───────────────────────────────────────────────────────────────
@app.route("/api/dnsdumpster", methods=["POST"])
@require_auth
def dnsdumpster():
    domain = request.json.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domaine requis"}), 400
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    audit("DNS_DUMPSTER", details=f"target={domain}")

    results = {"domain": domain, "a": [], "mx": [], "ns": [], "txt": [], "log": []}
    log = results["log"]
    log.append(f"[*] DNSDumpster — Cible: {domain}")
    log.append(f"[*] Heure: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.append("─" * 56)
    log.append("[*] Resolution enregistrements A / sous-domaines...")

    common_subs = ["www","mail","smtp","pop","imap","ftp","ns1","ns2","dev","staging","api",
                   "admin","portal","webmail","vpn","cdn","static","assets","blog","shop",
                   "store","m","mobile","app","secure","login","intranet","git","gitlab",
                   "jenkins","jira","confluence","remote","owa","exchange","autodiscover"]

    for sub in common_subs:
        hostname = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            results["a"].append({"host": hostname, "ip": ip})
            log.append(f"[+] {ip:<20} {hostname}")
        except socket.gaierror:
            pass

    if is_tool_available("dig"):
        log.append("[*] dig pour MX, NS, TXT...")
        for rtype, key in [("MX","mx"), ("NS","ns"), ("TXT","txt")]:
            out = run_cmd(f"dig {rtype} {domain} +short", timeout=15)
            for line in out.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith(";"): continue
                if rtype == "MX":
                    parts = line.split(); prio = parts[0] if len(parts)>=2 else "?"; host = parts[1].rstrip(".") if len(parts)>=2 else parts[0]
                    try: ip = socket.gethostbyname(host)
                    except: ip = "?"
                    results["mx"].append({"host": host, "ip": ip, "priority": prio})
                    log.append(f"[MX] {ip:<20} {host}  prio:{prio}")
                elif rtype == "NS":
                    h = line.rstrip(".")
                    try: ip = socket.gethostbyname(h)
                    except: ip = "?"
                    results["ns"].append({"host": h, "ip": ip})
                    log.append(f"[NS] {ip:<20} {h}")
                elif rtype == "TXT":
                    t = line.strip('"')
                    results["txt"].append(t); log.append(f"[TXT] {t}")
    elif is_tool_available("nslookup"):
        log.append("[*] nslookup...")
        mx_out = run_cmd(f"nslookup -type=MX {domain}", timeout=15)
        for line in mx_out.split("\n"):
            if "mail exchanger" in line.lower():
                parts = line.split("=")[-1].strip().split()
                if parts:
                    host = parts[-1].rstrip("."); prio = parts[0] if len(parts)>1 else "?"
                    try: ip = socket.gethostbyname(host)
                    except: ip = "?"
                    results["mx"].append({"host": host, "ip": ip, "priority": prio})
                    log.append(f"[MX] {ip:<20} {host}")
    else:
        log.append("[~] dig/nslookup absents")
        try:
            import dns.resolver
            for rtype in ["MX","NS","TXT"]:
                try:
                    for r in dns.resolver.resolve(domain, rtype):
                        if rtype=="MX":
                            h=str(r.exchange).rstrip(".")
                            try: ip=socket.gethostbyname(h)
                            except: ip="?"
                            results["mx"].append({"host":h,"ip":ip,"priority":str(r.preference)}); log.append(f"[MX] {ip:<20} {h}")
                        elif rtype=="NS":
                            h=str(r).rstrip(".")
                            try: ip=socket.gethostbyname(h)
                            except: ip="?"
                            results["ns"].append({"host":h,"ip":ip}); log.append(f"[NS] {ip:<20} {h}")
                        elif rtype=="TXT":
                            t=str(r).strip('"'); results["txt"].append(t); log.append(f"[TXT] {t}")
                except: pass
        except ImportError:
            log.append("[~] dnspython absent")

    log.append("─"*56)
    log.append(f"[OK] {len(results['a'])} sous-domaines, {len(results['mx'])} MX, {len(results['ns'])} NS")
    report_id = None
    if _auto_report_enabled("dnsdumpster"):
        report_id, _ = _save_scan_report(
            target=domain, dns_data=results, scan_output="\n".join(log),
            modules_run=["DNSDumpster"], auto=True,
        )
    results["report_id"] = report_id
    return jsonify(results)

# ── RECONNAISSANCE PASSIVE — dnsrecon (DNS + Certificate Transparency) ─────────
# Complète DNSDumpster : dnsrecon ajoute l'énumération de sous-domaines via les
# logs de Certificate Transparency (crt.sh) — 100 % passif, AUCUN paquet vers
# l'hôte cible — un relevé structuré des enregistrements DNS (A/AAAA/NS/MX/SOA/
# TXT/SRV) et une tentative de transfert de zone (AXFR, misconfig classique).
# Choix de l'outil : theHarvester (recommandé par le cahier des charges) n'existe
# sur PyPI qu'en stub v0.0.1 (même piège que enum4linux-ng) ; dnsrecon est fiable,
# léger et donne un JSON exploitable -> sections structurées plutôt qu'un dump
# brut. Le domaine est validé (forme domaine, pas IP) et dnsrecon est lancé en
# LISTE d'arguments (jamais shell=True) : la cible utilisateur n'est pas
# interpolée dans une chaîne shell (contrairement à run_cmd ailleurs).
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RECON_TYPES = {"std", "crt", "axfr"}  # std=records, crt=sous-domaines CT, axfr=transfert de zone

@app.route("/api/recon", methods=["POST"])
@require_auth
def recon_scan():
    data = request.json or {}
    domain = (data.get("domain", "") or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].strip().rstrip(".")
    if not domain:
        return jsonify({"error": "Domaine requis"}), 400
    # Recon passive = OSINT sur un NOM DE DOMAINE, pas une IP.
    try:
        ipaddress.ip_address(domain)
        return jsonify({"error": "Entrez un nom de domaine (ex : exemple.com), pas une adresse IP"}), 400
    except ValueError:
        pass
    if not _DOMAIN_RE.match(domain):
        return jsonify({"error": "Nom de domaine invalide"}), 400
    if not is_tool_available("dnsrecon"):
        return jsonify({"error": "dnsrecon non installé", "install": "pip install dnsrecon"}), 400

    modes = data.get("modes") or ["std", "crt"]
    types = [m for m in modes if m in RECON_TYPES] or ["std"]
    audit("RECON_PASSIVE", details=f"domain={domain} types={','.join(types)}")

    sections = {"hosts": [], "subdomains": [], "nameservers": [], "mail": [],
                "txt": [], "soa": [], "srv": [], "emails": []}
    log = [f"[*] Reconnaissance passive (dnsrecon) — {domain}",
           f"[*] Modules : {', '.join(types)}", "─" * 56]
    seen_sub, emails = set(), set()
    fd, jpath = tempfile.mkstemp(suffix=".json"); os.close(fd)
    try:
        # --lifetime borne chaque requête DNS ; -t liste les types choisis.
        cmd = ["dnsrecon", "-d", domain, "-t", ",".join(types), "-j", jpath, "--lifetime", "5"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
        except subprocess.TimeoutExpired:
            return jsonify({"error": "dnsrecon : délai dépassé (150s)"}), 504
        for stream in (proc.stdout, proc.stderr):
            s = (stream or "").strip()
            if s:
                log.append(s)
                emails.update(_EMAIL_RE.findall(s))
        try:
            with open(jpath) as f:
                records = json.load(f)
        except Exception:
            records = []
        for r in records:
            t = (r.get("type") or "").upper()
            name = r.get("name") or ""
            addr = r.get("address") or ""
            if t in ("A", "AAAA"):
                if name:
                    sections["hosts"].append({"host": name, "ip": addr})
                    if name.endswith("." + domain) and name not in seen_sub:
                        seen_sub.add(name); sections["subdomains"].append({"host": name, "ip": addr})
            elif t == "NS":
                sections["nameservers"].append({"host": r.get("target", ""), "ip": addr})
            elif t == "MX":
                sections["mail"].append({"host": r.get("exchange", ""), "ip": addr})
            elif t == "TXT":
                val = r.get("strings", "")
                sections["txt"].append(val)
                emails.update(_EMAIL_RE.findall(val))
            elif t == "SOA":
                sections["soa"].append({"host": r.get("mname", ""), "ip": addr})
            elif t == "SRV":
                sections["srv"].append({"host": r.get("name", ""), "target": r.get("target", ""),
                                        "port": r.get("port", ""), "ip": addr})
    finally:
        try: os.remove(jpath)
        except OSError: pass

    sections["emails"] = sorted(emails)
    total = sum(len(v) for v in sections.values())
    log.append("─" * 56)
    log.append(f"[+] {len(sections['subdomains'])} sous-domaine(s), {len(sections['hosts'])} hôte(s), "
               f"{len(sections['mail'])} MX, {len(sections['nameservers'])} NS, "
               f"{len(sections['emails'])} email(s), {len(sections['txt'])} TXT")

    report_id = None
    # Auto-rapport (Improvement 3) : seulement si des résultats existent.
    if total > 0 and _auto_report_enabled("recon"):
        # On dérive des "findings" légers à partir des sous-domaines/emails pour
        # que le rapport ait du contenu exploitable (surface d'attaque OSINT).
        vulns = []
        for s in sections["subdomains"][:50]:
            vulns.append({"severity": "low", "name": f"Sous-domaine exposé : {s['host']}",
                          "module": "Recon passive", "port": "", "cve": "N/A",
                          "recommendation": "Vérifier l'exposition et la nécessité de ce sous-domaine."})
        for e in sections["emails"][:20]:
            vulns.append({"severity": "low", "name": f"Email exposé : {e}",
                          "module": "Recon passive", "port": "", "cve": "N/A",
                          "recommendation": "Surface de phishing potentielle ; sensibiliser les porteurs."})
        report_id, _ = _save_scan_report(
            target=domain, vulnerabilities=vulns, dns_data=sections,
            scan_output="\n".join(log), modules_run=["Recon passive (dnsrecon)"], auto=True,
        )

    return jsonify({"ok": True, "domain": domain, "sections": sections,
                    "output": "\n".join(log), "report_id": report_id})

# ── NMAP ───────────────────────────────────────────────────────────────────────
# "full"/"udp"/"stealth" ont besoin de raw sockets / OS fingerprinting, donc de
# root - le seul cas dans toute l'app ou le conteneur (non-root depuis le
# hardening Docker, cf. CLAUDE.md) doit elever un sous-process. Plutot que de
# faire tourner tout le conteneur en root pour ces 3 types seulement, un
# sudoers carve-out tres etroit (deploy/docker/Dockerfile, /etc/sudoers.d/
# pentoolbox-nmap) autorise UNIQUEMENT ces 3 invocations nmap exactes — pinned
# sur le prefixe de flags, target reste une portion variable (wildcard cote
# sudoers). nmap n'impose pas d'ordre flags/cible: si target contenait un
# flag nmap (ex: "--script=...") ou un metacaractere shell, il s'executerait
# avec les privileges root accordes par sudo. _is_safe_scan_target() ferme
# cette possibilite pour ces 3 types specifiquement (les 3 autres ne sont pas
# elevés, donc pas concernes par ce risque).
_SAFE_SCAN_TARGET_RE = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9.:_-]*[a-zA-Z0-9])?(?:/\d{1,3})?$')
_NMAP_ELEVATED_TYPES = {"full", "udp", "stealth"}

def _is_safe_scan_target(target: str) -> bool:
    return bool(_SAFE_SCAN_TARGET_RE.match(target))

@app.route("/api/nmap", methods=["POST"])
@require_auth
def nmap_scan():
    data   = request.json
    target = data.get("target","").strip()
    stype  = data.get("type","default")
    if not target: return jsonify({"error":"Cible requise"}), 400
    if not is_tool_available("nmap"):
        msg = "[!] Nmap non trouve.\n    https://nmap.org/download.html" if platform.system()=="Windows" else "[!] sudo apt install nmap"
        return jsonify({"error":"Nmap non installe","output":msg}), 400
    if stype in _NMAP_ELEVATED_TYPES and not _is_safe_scan_target(target):
        return jsonify({"error": "Cible invalide pour ce type de scan (caracteres non autorises)"}), 400
    audit("NMAP_SCAN", details=f"target={target} type={stype}")
    # sudo -n uniquement sous Docker (ou le sudoers carve-out existe) et
    # uniquement pour les 3 types elevés - en standalone (python app.py /
    # .bat/.sh), pas de regle sudo presente: ces 3 types gardent leur
    # comportement standalone d'avant ce changement, inchange.
    _sudo = "sudo -n " if (stype in _NMAP_ELEVATED_TYPES and os.environ.get("DOCKER_ENV")) else ""
    cmds = {
        "default": f"nmap -sV -sC -T4 --open {target}",
        "quick":   f"nmap -T4 -F {target}",
        "full":    f"{_sudo}nmap -sV -sC -O -T4 -A --open {target}",
        "udp":     f"{_sudo}nmap -sU -T4 --top-ports 100 {target}",
        "vuln":    f"nmap -sV --script vuln -T4 {target}",
        "stealth": f"{_sudo}nmap -sS -T2 -f {target}",
    }
    start = time.time()
    output = run_cmd(cmds.get(stype, cmds["default"]), timeout=300)
    elapsed = round(time.time()-start, 2)
    report_id = None
    if not output.startswith("[!] Timeout") and "[!] Erreur" not in output:
        report_id = _maybe_auto_report("nmap", target, output, ["Nmap"])
    return jsonify({"target": target, "command": cmds.get(stype, cmds["default"]), "output": output, "elapsed": elapsed, "report_id": report_id})

# ── DNS LOOKUP ─────────────────────────────────────────────────────────────────
@app.route("/api/dns", methods=["POST"])
@require_auth
def dns_lookup():
    data   = request.json
    target = data.get("target","").strip()
    rtype  = data.get("type","A")
    if not target: return jsonify({"error":"Cible requise"}), 400
    audit("DNS_LOOKUP", details=f"target={target} type={rtype}")
    if is_tool_available("dig"):       output = run_cmd(f"dig {rtype} {target}", timeout=15)
    elif is_tool_available("nslookup"):output = run_cmd(f"nslookup -type={rtype} {target}", timeout=15)
    else:
        try:
            ips = socket.getaddrinfo(target, None)
            output = f"; DNS Lookup (Python socket)\n" + "\n".join(f"{target}  {rtype}  {ip[4][0]}" for ip in ips)
        except Exception as e:
            output = f"[!] Erreur: {e}"
    return jsonify({"target": target, "type": rtype, "output": output})

# ── NIKTO ──────────────────────────────────────────────────────────────────────
@app.route("/api/nikto", methods=["POST"])
@require_auth
def nikto_scan():
    target = request.json.get("target","").strip()
    if not target: return jsonify({"error":"Cible requise"}), 400
    if not is_tool_available("nikto"): return jsonify({"error":"Nikto non installe","install":"sudo apt install nikto"}), 400
    # Auto-détection HTTPS si le port est connu HTTPS ou si https:// est précisé
    if not target.startswith("http"):
        # Ports HTTPS courants
        https_ports = ["443","8443","1280","8080","4443","10443"]
        port = target.split(":")[-1] if ":" in target else ""
        if port in https_ports:
            target = "https://" + target
        else:
            target = "http://" + target

    audit("NIKTO_SCAN", details=f"target={target}")
    start = time.time()
    # -nointeractive -ssl pour forcer SSL, -nolookup pour éviter DNS lent
    # -Tuning x pour ignorer les erreurs SSL
    # Test de connectivité d'abord
    test_cmd = f"curl -sk --connect-timeout 5 {target} -o /dev/null -w '%{{http_code}}' 2>&1"
    http_code = run_cmd(test_cmd, timeout=10).strip()
    
    if http_code in ['000', ''] or 'failed' in http_code.lower():
        out = f"[!] Impossible de joindre {target} depuis le container Docker.\n"
        out += f"[*] Code HTTP recu: {http_code}\n"
        out += f"[*] Solutions:\n"
        out += f"    1. Utilisez l'IP reelle au lieu du hostname (ex: 192.168.1.x:1280)\n"
        out += f"    2. Assurez-vous que la cible est sur le meme reseau\n"
        out += f"    3. Verifiez que le port est ouvert avec Nmap d'abord"
    else:
        cmd = f"nikto -h {target} -nointeractive -ssl -nolookup -timeout 15 -maxtime 300"
        out = run_cmd(cmd, timeout=180)
        if not out.strip() or out.strip() == '- Nikto v2.6.0\n---------------------------------------------------------------------------':
            out += f"\n[*] Nikto n'a trouve aucune vulnerabilite evidente sur {target}\n"
            out += f"[*] Cela peut indiquer que la cible est bien securisee ou necessite une authentification."
    elapsed = round(time.time()-start,2)
    # Auto-rapport si Nikto a réellement remonté des items (lignes "+ ..." avec
    # un identifiant OSVDB/CVE ou une description). Pas de rapport si RAS.
    report_id = None
    nikto_findings = [l for l in out.splitlines() if re.match(r"^\+ ", l)
                      and not re.search(r"Target (IP|Hostname|Port)|Start Time|Server:|retrieved", l)]
    if nikto_findings:
        vulns = [{"severity": "medium" if re.search(r"OSVDB|CVE-|XSS|inject|disclos", f, re.I) else "low",
                  "name": f.lstrip("+ ").strip()[:200], "module": "Nikto", "port": "",
                  "cve": (re.search(r"CVE-\d{4}-\d+", f) or [None])[0] if re.search(r"CVE-\d{4}-\d+", f) else "N/A",
                  "recommendation": "Vérifier et corriger la configuration/version du serveur web."}
                 for f in nikto_findings[:60]]
        report_id = _maybe_auto_report("nikto", target, out, ["Nikto"], vulnerabilities=vulns)
    return jsonify({"target": target, "output": out, "elapsed": elapsed, "report_id": report_id})

# ── SQLMAP ─────────────────────────────────────────────────────────────────────
# Tampers WAF-bypass les plus courants (whitelist -> pas de --tamper arbitraire).
SQLMAP_TAMPERS = [
    "space2comment", "between", "randomcase", "charencode", "charunicodeencode",
    "apostrophemask", "equaltolike", "percentage", "versionedmorekeywords", "base64encode",
]

@app.route("/api/sqlmap", methods=["POST"])
@require_auth
def sqlmap_scan():
    data   = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "URL requise"}), 400
    if not is_tool_available("sqlmap"):
        return jsonify({"error": "SQLMap non installe", "install": "pip install sqlmap"}), 400

    # Technique : sous-ensemble de B(oolean) E(rror) U(nion) S(tacked) T(ime) Q(uery).
    # Vide => auto (sqlmap teste toutes les techniques par défaut).
    technique = "".join(c for c in (data.get("technique") or "").upper() if c in "BEUSTQ")
    # level 1-5 ; risk 1-3 (sqlmap n'accepte PAS risk>3, contrairement au level).
    try:    level = max(1, min(5, int(data.get("level", 1))))
    except (TypeError, ValueError): level = 1
    try:    risk = max(1, min(3, int(data.get("risk", 1))))
    except (TypeError, ValueError): risk = 1
    toggles = data.get("toggles") or {}
    try:    crawl = max(0, min(5, int(data.get("crawl", 0))))
    except (TypeError, ValueError): crawl = 0
    tampers = [t for t in (data.get("tamper") or []) if t in SQLMAP_TAMPERS]

    parts = [f'sqlmap -u "{target}"', "--batch", "--banner",
             f"--level={level}", f"--risk={risk}"]
    if technique:
        parts.append(f"--technique={technique}")
    if toggles.get("forms"):  parts.append("--forms")
    if crawl:                 parts.append(f"--crawl={crawl}")
    if toggles.get("dbs"):    parts.append("--dbs")
    if toggles.get("tables"): parts.append("--tables")
    if toggles.get("dump"):   parts.append("--dump")
    if tampers:               parts.append("--tamper=" + ",".join(tampers))
    cmd = " ".join(parts) + " 2>&1 | head -250"

    audit("SQLMAP_SCAN", details=f"target={target} technique={technique or 'auto'} level={level} risk={risk} dump={bool(toggles.get('dump'))}")
    start = time.time()
    # --dump / --crawl peuvent être longs -> timeout aligné sur les autres scans lourds.
    out = run_cmd(cmd, timeout=180)
    elapsed = round(time.time() - start, 2)
    out = f"[*] Commande: {cmd}\n[*] Durée: {elapsed}s\n\n" + out
    # Auto-rapport seulement si sqlmap a trouvé une injection / un paramètre
    # vulnérable (sinon pas de findings -> pas de rapport).
    report_id = None
    if re.search(r"is vulnerable|appears to be injectable|sqlmap identified the following injection|Parameter:\s", out, re.I):
        params = re.findall(r"Parameter:\s*([^\n(]+)", out)
        vulns = [{"severity": "high", "name": f"Injection SQL — paramètre {p.strip()}",
                  "module": "SQLMap", "port": "", "cve": "N/A",
                  "recommendation": "Paramétrer les requêtes (requêtes préparées), valider les entrées."}
                 for p in (params or ["(détectée)"])[:20]]
        report_id = _maybe_auto_report("sqlmap", target, out, ["SQLMap"], vulnerabilities=vulns)
    return jsonify({"target": target, "output": out, "elapsed": elapsed, "report_id": report_id})

@app.route("/api/sqlmap/tampers")
@require_auth
def sqlmap_tampers():
    return jsonify({"tampers": SQLMAP_TAMPERS})

# ── OPENVAS ────────────────────────────────────────────────────────────────────
@app.route("/api/openvas/port_lists")
@require_auth
def openvas_port_lists():
    """
    Alimente le selecteur de port list de l'UI OpenVAS. Renvoie les presets
    Greenbone (resolus A CHAUD par nom via <get_port_lists/> -> pas d'UUID code
    en dur cote app) + la port list custom "Top 100 TCP" (creee au besoin), avec
    l'id du choix par defaut. Une option "Custom" (plage saisie a la main) est
    geree cote POST /api/scan/openvas via le champ custom_ports.
    """
    if not is_tool_available("gvm-cli"):
        return jsonify({"error": "gvm-cli non installe", "install": "pip install gvm-tools"}), 400
    try:
        live = _get_port_lists()
        # Top 100 TCP: absente des flux Greenbone -> on s'assure qu'elle existe
        # (idempotent, reutilisee par nom) puis on rafraichit la liste live.
        _ensure_port_list(OPENVAS_TOP100_TCP_NAME, OPENVAS_TOP100_TCP_RANGE)
        live = _get_port_lists()
        by_name = {pl["name"]: pl for pl in live}

        options = []
        for name in OPENVAS_PRESET_PORT_LISTS + [OPENVAS_TOP100_TCP_NAME]:
            pl = by_name.get(name)
            if pl:
                options.append({"id": pl["id"], "name": name, "count": pl["count"]})

        default_id = (by_name.get(OPENVAS_DEFAULT_PORT_LIST_NAME) or {}).get("id")
        return jsonify({"port_lists": options, "default_id": default_id})
    except OpenVASError as e:
        return jsonify({"error": str(e)}), 503

@app.route("/api/scan/openvas", methods=["POST"])
@require_auth
def openvas_scan():
    """
    Demarre un scan de vulnerabilites OpenVAS/GVM en arriere-plan.
    A la difference des autres routes (nmap, nikto...), un scan complet dure
    de plusieurs minutes a plusieurs heures: on ne bloque donc pas la requete
    HTTP comme run_cmd() le fait ailleurs. On renvoie un job_id tout de suite
    et le client recupere l'avancement via GET /api/scan/openvas/<job_id>.
    Port list: `port_list_id` (preset choisi dans l'UI) ou `custom_ports` (plage
    saisie a la main) ; defaut OPENVAS_DEFAULT_PORT_LIST_NAME si rien n'est passe.
    """
    _prune_openvas_jobs()
    body          = request.json or {}
    target        = body.get("target", "").strip()
    port_list_id  = (body.get("port_list_id") or "").strip()
    custom_ports  = (body.get("custom_ports") or "").strip()
    if not target:
        return jsonify({"error": "Cible requise"}), 400

    if not is_tool_available("gvm-cli"):
        return jsonify({"error": "gvm-cli non installe", "install": "pip install gvm-tools"}), 400

    # Sonde rapide (get_version) pour distinguer "conteneur OpenVAS pas pret"
    # d'une vraie erreur de scan, avant de lancer le thread de fond.
    try:
        _gvm_command("<get_version/>", timeout=10)
    except OpenVASError as e:
        audit("OPENVAS_UNAVAILABLE", details=f"target={target} error={e}")
        return jsonify({"error": str(e)}), 503

    # Resolution de la port list AVANT de lancer le thread: une plage invalide ou
    # un id inconnu doit renvoyer une vraie erreur HTTP, pas finir en job "error".
    try:
        port_list_id, port_list_label = _resolve_scan_port_list(port_list_id, custom_ports)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except OpenVASError as e:
        return jsonify({"error": str(e)}), 503

    job_id = str(uuid.uuid4())
    user   = get_current_user()
    with OPENVAS_JOBS_LOCK:
        OPENVAS_JOBS[job_id] = {
            "status": "starting", "target": target,
            "port_list": port_list_label, "started_at": time.time(),
        }

    audit("OPENVAS_SCAN_START", details=f"job={job_id} target={target} port_list={port_list_label}")

    threading.Thread(
        target=_openvas_worker, args=(job_id, target, user, port_list_id), daemon=True,
    ).start()

    return jsonify({"ok": True, "job_id": job_id, "status": "starting", "port_list": port_list_label}), 202

@app.route("/api/scan/openvas/<job_id>")
@require_auth
def openvas_poll(job_id):
    """Etat d'avancement d'un scan OpenVAS declenche par /api/scan/openvas."""
    with OPENVAS_JOBS_LOCK:
        job = OPENVAS_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify({"job_id": job_id, **job})

# ── METASPLOIT ───────────────────────────────────────────────────────────────
@app.route("/api/msf/modules")
@require_auth
def msf_modules():
    """
    Source unique de verite pour le <select> du frontend: les memes cles que
    MSF_ALLOWED_MODULES verifiees par /api/scan/msf, pour que l'UI ne puisse
    jamais proposer un module que la route refuserait de toute facon.
    """
    avail = _msf_available_set()  # None si RPC injoignable
    out = {}
    for mid, m in MSF_ALLOWED_MODULES.items():
        out[mid] = {
            "label": m["label"],
            "options": m["options"],
            "category": m.get("category", "autre"),
            "is_exploit": mid.startswith("exploit/"),
            "available": (mid in avail) if avail is not None else False,
            "rpc_down": avail is None,
        }
    return jsonify(out)

@app.route("/api/scan/msf", methods=["POST"])
@require_auth
def msf_scan():
    """
    Demarre un module Metasploit (auxiliary/scanner ou exploit/* whiteliste)
    en arriere-plan, meme mecanique async que /api/scan/openvas (job_id +
    poll) car msfrpcd est un demon long-running, pas un binaire one-shot
    comme nmap/nikto.
    """
    _prune_msf_jobs()
    data = request.json or {}
    target = data.get("target", "").strip()
    module = data.get("module", "")
    if not target:
        return jsonify({"error": "Cible requise"}), 400

    # La vraie barriere de scope: rejet serveur de tout module hors
    # whitelist, quoi que le frontend ait pu envoyer.
    module_spec = MSF_ALLOWED_MODULES.get(module)
    if not module_spec:
        return jsonify({"error": f"Module non autorise: {module}"}), 400

    # Les exploits accordent un shell distant: leur cible est en plus
    # verifiee contre les sous-reseaux autorises (reglage en base, repli sur
    # ALLOWED_EXPLOIT_SUBNETS — deny-by-default si ni l'un ni l'autre n'est
    # configure). Les auxiliary/scanner restent sans restriction de cible
    # (recon non destructive).
    if module.startswith("exploit/") and not _target_in_allowed_exploit_subnets(target):
        audit("MSF_EXPLOIT_TARGET_REJECTED", details=f"target={target} module={module}")
        return jsonify({
            "error": "Cible hors du perimetre labo autorise pour les modules exploit/* "
                     "(voir ALLOWED_EXPLOIT_SUBNETS)",
        }), 403

    # Seules les cles d'option whitelistees pour ce module sont retenues -
    # empeche d'injecter PAYLOAD ou toute autre option hors de la liste
    # explicite de module_spec["options"] via le body (LHOST/LPORT y figurent
    # deliberement pour usermap_script, cf. MSF_ALLOWED_MODULES).
    raw_options = data.get("options") or {}
    options = {k: v for k, v in raw_options.items() if k in module_spec["options"]}
    if "RHOSTS" in module_spec["options"] and "RHOSTS" not in options:
        options["RHOSTS"] = target

    try:
        _msf_probe(timeout=10)
    except MetasploitError as e:
        audit("MSF_UNAVAILABLE", details=f"target={target} module={module} error={e}")
        return jsonify({"error": str(e)}), 503

    job_id = str(uuid.uuid4())
    user   = get_current_user()
    with MSF_JOBS_LOCK:
        MSF_JOBS[job_id] = {"status": "starting", "target": target, "module": module, "started_at": time.time()}

    audit("MSF_SCAN_START", details=f"job={job_id} target={target} module={module}")

    threading.Thread(target=_msf_worker, args=(job_id, module, target, options, user), daemon=True).start()

    return jsonify({"ok": True, "job_id": job_id, "status": "starting"}), 202

@app.route("/api/scan/msf/<job_id>")
@require_auth
def msf_poll(job_id):
    """Etat d'avancement d'un scan Metasploit declenche par /api/scan/msf."""
    with MSF_JOBS_LOCK:
        job = MSF_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job_id inconnu"}), 404
    return jsonify({"job_id": job_id, **job})

# ── HYDRA ──────────────────────────────────────────────────────────────────────
# ── ARRÊTER UN SCAN ──────────────────────────────────────────────────────────
@app.route("/api/stop-scan", methods=["POST"])
@require_auth
def stop_scan():
    """Arrête un scan en cours (nmap, nikto, sqlmap, openvas, etc.)"""
    import psutil
    import signal
    import os
    
    data = request.json or {}
    scan_type = data.get("scan", "").strip().lower()

    if not scan_type:
        return jsonify({"ok": False, "message": "Type de scan requis"}), 400

    # OpenVAS est un cas a part : le scan ne tourne PAS comme un process local
    # dans ce conteneur (gvmd vit dans le conteneur 'openvas'), donc psutil ne
    # peut pas le trouver/tuer — et tuer gvmd serait catastrophique (arrete tout
    # le scanner). Le bon mecanisme est la commande GMP <stop_task>.
    if scan_type == "openvas":
        job_id = (data.get("job_id") or "").strip()
        targets = []  # liste de (job_id, task_id) a arreter
        with OPENVAS_JOBS_LOCK:
            if job_id and job_id in OPENVAS_JOBS:
                tid = OPENVAS_JOBS[job_id].get("task_id")
                if tid:
                    targets.append((job_id, tid))
            elif not job_id:
                # Pas de job_id fourni -> on arrete tous les scans OpenVAS actifs.
                for jid, j in OPENVAS_JOBS.items():
                    if j.get("status") in ("starting", "running") and j.get("task_id"):
                        targets.append((jid, j["task_id"]))
        if not targets:
            return jsonify({"ok": False, "message": "Aucun scan OpenVAS en cours à arrêter (le scan n'a peut-être pas encore créé sa tâche gvmd)."}), 404
        stopped, errors = 0, []
        for jid, tid in targets:
            try:
                _gvm_command(f'<stop_task task_id="{tid}"/>', timeout=30)
                with OPENVAS_JOBS_LOCK:
                    if jid in OPENVAS_JOBS:
                        OPENVAS_JOBS[jid]["status"] = "stopping"
                stopped += 1
            except Exception as e:
                errors.append(str(e))
        audit("SCAN_STOP", details=f"scan=openvas stopped={stopped} tasks={[t for _, t in targets]}")
        if stopped:
            return jsonify({"ok": True, "message": f"Demande d'arrêt envoyée à gvmd ({stopped} tâche(s)). Le scan s'arrêtera sous peu."})
        return jsonify({"ok": False, "message": "Échec de l'arrêt OpenVAS : " + "; ".join(errors)}), 502

    try:
        # Mapper les noms aux noms de processus
        process_names = {
            "nmap": "nmap",
            "nikto": "nikto.pl",
            "sqlmap": "sqlmap",
            "scan_reseau": "nmap",
            "exploit_auto": "nmap",
        }
        
        process_name = process_names.get(scan_type)
        if not process_name:
            return jsonify({"ok": False, "message": f"Type de scan inconnu: {scan_type}"}), 400
        
        # Tuer tous les processus correspondants avec Python
        killed_count = 0
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if process_name.lower() in proc.name().lower() or \
                   (proc.cmdline() and process_name.lower() in ' '.join(proc.cmdline()).lower()):
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        audit("SCAN_STOP", details=f"scan={scan_type} killed={killed_count}")
        msg = f"Scan {scan_type} arrêté" if killed_count > 0 else f"Aucun processus {scan_type} trouvé"
        return jsonify({"ok": True, "message": msg})
    except Exception as e:
        audit("SCAN_STOP_ERROR", details=f"scan={scan_type} error={str(e)}")
        return jsonify({"ok": False, "message": f"Erreur arrêt scan: {str(e)}"}), 500


# ── Wordlists Hydra ───────────────────────────────────────────────────────────
# Deux familles :
#  - intégrées (toujours disponibles) : petites listes curées, écrites dans un
#    fichier temporaire au moment du scan.
#  - fichiers système (rockyou, SecLists…) : détectés sur disque ; n'apparaissent
#    dans l'UI que s'ils existent (cf. /api/hydra/wordlists). L'image Docker en
#    embarque (voir Dockerfile : /usr/share/wordlists/), et on détecte aussi les
#    emplacements Kali standard si l'app tourne en natif.
HYDRA_BUILTIN_WORDLISTS = {
    "common":       ["admin", "password", "123456", "root", "toor", "pass", "test", "guest", "admin123", "password123"],
    "ssh-defaults": ["root", "toor", "admin", "msfadmin", "ubuntu", "pi", "raspberry", "user", "test", "guest", "vagrant", "kali", "password"],
    "ftp-defaults": ["anonymous", "ftp", "admin", "user", "root", "test", "msfadmin", "guest"],
}
# id -> chemins candidats (premier existant gagne). Ordre = préférence d'affichage.
HYDRA_WORDLIST_FILES = [
    {"id": "rockyou",        "label": "rockyou.txt",        "paths": ["/usr/share/wordlists/rockyou.txt"]},
    {"id": "unix_passwords", "label": "unix_passwords.txt", "paths": ["/usr/share/wordlists/unix_passwords.txt", "/usr/share/seclists/Passwords/unix_passwords.txt", "/usr/share/wordlists/seclists/Passwords/unix_passwords.txt"]},
    {"id": "ssh_passwords",  "label": "SSH default creds",  "paths": ["/usr/share/wordlists/ssh-betterdefaultpasslist.txt", "/usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt", "/usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt"]},
    {"id": "fasttrack",      "label": "fasttrack.txt",      "paths": ["/usr/share/wordlists/fasttrack.txt", "/usr/share/set/src/fasttrack/wordlist.txt"]},
]

def _resolve_wordlist_file(wl_id):
    """Renvoie le 1er chemin existant pour un id de wordlist fichier, sinon None."""
    for entry in HYDRA_WORDLIST_FILES:
        if entry["id"] == wl_id:
            for p in entry["paths"]:
                if os.path.isfile(p):
                    return p
            return None
    return None

# ── Listes de noms d'utilisateur (Hydra -L) ──────────────────────────────────
# Symétrique des wordlists de mots de passe ci-dessus : intégrées (toujours
# dispo) + fichiers système (SecLists/Metasploit, détectés sur disque).
HYDRA_BUILTIN_USERLISTS = {
    # Comptes par défaut courants SSH / services. Inclut msfadmin (Metasploitable)
    # et administrator (Windows) en plus de la liste classique demandée.
    "ssh-users": ["root", "admin", "administrator", "msfadmin", "ubuntu", "pi",
                  "vagrant", "ansible", "deploy", "git", "oracle", "postgres",
                  "mysql", "user", "test", "guest"],
}
HYDRA_USERLIST_FILES = [
    {"id": "seclists-top", "label": "SecLists top-usernames",
     "paths": ["/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
               "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"]},
    {"id": "msf-common",   "label": "Metasploit common_users",
     "paths": ["/usr/share/metasploit-framework/data/wordlists/common_users.txt"]},
    {"id": "unix_users",   "label": "unix_users.txt",
     "paths": ["/usr/share/wordlists/unix_users.txt",
               "/usr/share/seclists/Usernames/unix_users.txt",
               "/usr/share/wordlists/seclists/Usernames/Names/names.txt"]},
]

def _resolve_userlist_file(ul_id):
    """Renvoie le 1er chemin existant pour un id de userlist fichier, sinon None."""
    for entry in HYDRA_USERLIST_FILES:
        if entry["id"] == ul_id:
            for p in entry["paths"]:
                if os.path.isfile(p):
                    return p
            return None
    return None

# Validation des chemins de fichiers fournis par l'utilisateur (wordlist/userlist
# custom) : interpolés dans une commande shell=True -> on n'autorise qu'un chemin
# de fichier existant sans métacaractère shell ni espace.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
def _is_safe_existing_path(p):
    return bool(p) and bool(_SAFE_PATH_RE.match(p)) and os.path.isfile(p)

# Nom d'utilisateur unique (-l) : interpolé dans le shell -> charset restreint
# (autorise DOMAIN\user pour SMB, refuse espaces et métacaractères).
_SAFE_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,64}$")

@app.route("/api/hydra/wordlists")
@require_auth
def hydra_wordlists():
    """Liste les wordlists proposables (intégrées + fichiers présents sur le système)."""
    out = []
    for wid, words in HYDRA_BUILTIN_WORDLISTS.items():
        out.append({"id": wid, "label": {"common": "Commune", "ssh-defaults": "SSH defaults", "ftp-defaults": "FTP defaults"}.get(wid, wid),
                    "builtin": True, "available": True, "count": len(words)})
    for entry in HYDRA_WORDLIST_FILES:
        path = _resolve_wordlist_file(entry["id"])
        item = {"id": entry["id"], "label": entry["label"], "builtin": False, "available": path is not None}
        if path:
            try:
                # wc -l sans charger le fichier en RAM (rockyou ≈ 14M lignes).
                with open(path, "rb") as f:
                    item["count"] = sum(buf.count(b"\n") for buf in iter(lambda: f.read(1 << 20), b""))
                item["path"] = path
            except Exception:
                pass
        out.append(item)

    # Listes de noms d'utilisateur (pour le sélecteur -l/-L côté UI).
    userlists = []
    for uid, users in HYDRA_BUILTIN_USERLISTS.items():
        userlists.append({"id": uid, "label": "SSH defaults (intégrée)",
                          "builtin": True, "available": True, "count": len(users)})
    for entry in HYDRA_USERLIST_FILES:
        path = _resolve_userlist_file(entry["id"])
        item = {"id": entry["id"], "label": entry["label"], "builtin": False, "available": path is not None}
        if path:
            try:
                with open(path, "rb") as f:
                    item["count"] = sum(buf.count(b"\n") for buf in iter(lambda: f.read(1 << 20), b""))
                item["path"] = path
            except Exception:
                pass
        userlists.append(item)

    return jsonify({"wordlists": out, "userlists": userlists})

@app.route("/api/hydra", methods=["POST"])
@require_auth
def hydra_scan():
    data     = request.json
    target   = data.get("target", "").strip()
    service  = data.get("service", "ssh")
    username = data.get("username", "admin").strip()
    wordlist = data.get("wordlist", "common")
    # Source du/des nom(s) d'utilisateur : single (-l), builtin/filelist/custom (-L).
    user_source     = data.get("user_source", "single")
    userlist        = data.get("userlist", "")
    custom_userlist = data.get("custom_userlist", "").strip()
    if not target:
        return jsonify({"error": "Cible requise"}), 400
    if not is_tool_available("hydra"):
        return jsonify({"error": "Hydra non installe", "install": "sudo apt install hydra"}), 400

    # Construit le fragment -l/-L et valide l'entrée (interpolée dans shell=True).
    user_arg = None
    user_tmp_to_clean = None
    if user_source == "single":
        if not username:
            username = "admin"
        if not _SAFE_USERNAME_RE.match(username):
            return jsonify({"error": "Nom d'utilisateur invalide (caractères non autorisés)."}), 400
        user_arg = f"-l {username}"
        user_label = username
    elif user_source == "builtin":
        if userlist not in HYDRA_BUILTIN_USERLISTS:
            return jsonify({"error": f"Liste d'utilisateurs '{userlist}' inconnue."}), 400
        import tempfile
        uf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        uf.write("\n".join(HYDRA_BUILTIN_USERLISTS[userlist]))
        uf.close()
        user_arg = f"-L {uf.name}"
        user_tmp_to_clean = uf.name
        user_label = f"liste:{userlist}"
    elif user_source == "filelist":
        up = _resolve_userlist_file(userlist)
        if not up:
            return jsonify({"error": f"Liste d'utilisateurs '{userlist}' indisponible sur ce système."}), 400
        user_arg = f"-L {up}"
        user_label = f"fichier:{userlist}"
    elif user_source == "custom":
        if not _is_safe_existing_path(custom_userlist):
            return jsonify({"error": "Chemin de liste d'utilisateurs invalide ou introuvable."}), 400
        user_arg = f"-L {custom_userlist}"
        user_label = f"custom:{custom_userlist}"
    else:
        return jsonify({"error": f"Source d'utilisateur inconnue: {user_source}"}), 400

    audit("HYDRA_SCAN", details=f"target={target} service={service} user={user_label} wordlist={wordlist}")

    # Résolution de la wordlist : fichier système (rockyou…) ou liste intégrée.
    wf_path = None        # chemin -P final
    tmp_to_clean = None   # fichier temp à supprimer (listes intégrées seulement)
    if wordlist in HYDRA_BUILTIN_WORDLISTS:
        import tempfile
        wf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        wf.write("\n".join(HYDRA_BUILTIN_WORDLISTS[wordlist]))
        wf.close()
        wf_path = tmp_to_clean = wf.name
    else:
        wf_path = _resolve_wordlist_file(wordlist)
        if not wf_path:
            return jsonify({"error": f"Wordlist '{wordlist}' indisponible sur ce système."}), 400

    try:
        # -e nsr : teste aussi mot de passe vide (n), login=password (s) et login
        #          inversé (r), en plus de la wordlist (utile sur cibles laxistes).
        # -I     : ignore un éventuel ./hydra.restore résiduel (sinon hydra refuse
        #          de démarrer en demandant quoi en faire).
        # Les algos SSH legacy (Metasploitable 2 : ssh-rsa/ssh-dss, KEX/MAC
        # obsolètes) sont gérés en amont par libssh via /etc/ssh/ssh_config.d/
        # 99-pentoolbox-legacy.conf (cf. Dockerfile) — hydra n'a pas de flag KEX.
        cmd = f"hydra {user_arg} -P {wf_path} -e nsr -I -t 4 -f {service}://{target}"
        start_time = time.time()
        output = run_cmd(cmd, timeout=180)
        elapsed = round(time.time() - start_time, 2)
        output = f"[*] Commande: {cmd}\n[*] Duree: {elapsed}s\n\n" + output
    finally:
        if tmp_to_clean:
            os.unlink(tmp_to_clean)
        if user_tmp_to_clean:
            os.unlink(user_tmp_to_clean)

    # Auto-rapport si des identifiants valides ont été trouvés (sinon RAS, pas
    # de rapport). Format Hydra : "[port][service] host: H login: L password: P".
    report_id = None
    creds = re.findall(r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S*)", output)
    if creds:
        vulns = [{"severity": "critical", "name": f"Identifiant valide {svc} : {login} / {(pw or '(vide)')}",
                  "module": "Hydra", "port": port, "cve": "N/A",
                  "recommendation": "Changer le mot de passe, imposer une politique forte, restreindre l'accès."}
                 for (port, svc, host, login, pw) in creds[:30]]
        report_id = _maybe_auto_report("hydra", target, output, [f"Hydra:{service}"], vulnerabilities=vulns)
    return jsonify({"target": target, "service": service, "output": output,
                    "elapsed": elapsed, "report_id": report_id})


# ── ÉNUMÉRATION SMB / NetBIOS (enum4linux-ng) ─────────────────────────────────
# Remplace l'ancien "Scan Réseau" (qui doublonnait la découverte d'hôtes de
# Nmap). enum4linux-ng apporte une capacité absente jusqu'ici : énumération SMB/
# NetBIOS/LDAP (partages, utilisateurs, groupes, politique de mot de passe, OS,
# dialecte/signature SMB) — très utile contre les cibles Windows/Samba.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")  # enum4linux-ng colore toujours sa sortie

ENUM4LINUX_MODES = {
    "all":    ["-A"],            # énumération complète
    "shares": ["-S"],           # partages
    "users":  ["-U", "-G"],     # utilisateurs + groupes
    "os":     ["-O", "-P"],     # OS + politique de mots de passe
}

@app.route("/api/enum4linux", methods=["POST"])
@require_auth
def enum4linux_scan():
    data     = request.json or {}
    target   = data.get("target", "").strip()
    mode     = data.get("mode", "all")
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not target:
        return jsonify({"error": "Cible requise"}), 400
    # Cible interpolée dans une commande shell -> validation de forme (host/IP),
    # contrairement aux routes historiques qui laissent passer la cible brute.
    if not _is_safe_scan_target(target):
        return jsonify({"error": "Cible invalide (hôte ou IP attendu, ex: 192.168.56.109)."}), 400
    if not is_tool_available("enum4linux-ng"):
        return jsonify({"error": "enum4linux-ng non installé",
                        "install": "git clone https://github.com/cddmp/enum4linux-ng + pip install ldap3 pyyaml impacket (voir Dockerfile)"}), 400

    flags = ENUM4LINUX_MODES.get(mode, ENUM4LINUX_MODES["all"])
    audit("ENUM4LINUX", details=f"target={target} mode={mode}")
    cred = ""
    if username:
        cred = f" -u {shlex.quote(username)}"
        if password:
            cred += f" -p {shlex.quote(password)}"
    cmd = f"enum4linux-ng {' '.join(flags)}{cred} {target}"
    start_time = time.time()
    output = run_cmd(cmd, timeout=180)
    elapsed = round(time.time() - start_time, 2)
    output = _ANSI_RE.sub("", output)  # retire les codes couleur ANSI pour le terminal web
    output = f"[*] Commande: {cmd}\n[*] Durée: {elapsed}s\n\n" + output
    # Auto-rapport si l'énumération a produit des trouvailles (lignes "[+]").
    report_id = None
    hits = len(re.findall(r"^\s*\[\+\]", output, re.M))
    if hits:
        report_id = _maybe_auto_report("enum4linux", target, output, [f"enum4linux-ng:{mode}"])
    return jsonify({"target": target, "mode": mode, "output": output,
                    "elapsed": elapsed, "report_id": report_id})


# ── CRACKING DE HASHES (John the Ripper, jumbo) ───────────────────────────────
# Page "Cracking" (post-exploitation). On lance john en arrière-plan (Popen) en
# écrivant les hashes dans un fichier de session isolé, puis on POLL son
# avancement : `john --show` lit le .pot et renvoie les identifiants déchiffrés
# au fur et à mesure (≈ streaming). Stop = terminate du process.
#
# john est appelé via une LISTE d'arguments (pas shell=True) : le contenu des
# hashes (collés par l'utilisateur) n'est jamais interprété par un shell.
JOHN_FORMATS = {
    # label UI -> nom de format john (None = auto-détection, pas de --format)
    "auto":        None,
    "md5":         "Raw-MD5",
    "sha1":        "Raw-SHA1",
    "sha256":      "Raw-SHA256",
    "bcrypt":      "bcrypt",
    "ntlm":        "NT",
    "md5crypt":    "md5crypt",
    "sha512crypt": "sha512crypt",
}
JOHN_RULES = {"none": None, "best64": "Best64", "jumbo": "Jumbo"}
JOHN_JOBS = {}  # job_id -> {proc, dir, hashfile, potfile, fmt, started}

def _john_bin():
    return shutil.which("john")

def _john_parse_show(text):
    """Parse la sortie de `john --show` -> [{user, password}]. La dernière ligne
    est un résumé ('N password hashes cracked, M left') -> ignorée."""
    creds = []
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line or ":" not in line:
            continue
        if "password hash" in line.lower() or "cracked" in line.lower():
            continue  # ligne de résumé
        parts = line.split(":")
        user = parts[0] if parts[0] else "(hash)"
        pwd = parts[1] if len(parts) > 1 else ""
        creds.append({"user": user, "password": pwd})
    return creds

@app.route("/api/john/start", methods=["POST"])
@require_auth
def john_start():
    if not _john_bin():
        return jsonify({"error": "John the Ripper non installé",
                        "install": "build openwall/john (jumbo) ou apt install john"}), 400
    data = request.json or {}
    hashes = (data.get("hashes", "") or "").strip()
    fmt    = data.get("format", "auto")
    rules  = data.get("rules", "none")
    wordlist        = data.get("wordlist", "rockyou")
    custom_wordlist = (data.get("custom_wordlist", "") or "").strip()
    if not hashes:
        return jsonify({"error": "Aucun hash fourni."}), 400
    if fmt not in JOHN_FORMATS:
        return jsonify({"error": f"Format inconnu: {fmt}"}), 400
    if rules not in JOHN_RULES:
        return jsonify({"error": f"Règles inconnues: {rules}"}), 400

    # Résolution de la wordlist (réutilise les fichiers détectés pour Hydra).
    if custom_wordlist:
        if not _is_safe_existing_path(custom_wordlist):
            return jsonify({"error": "Chemin de wordlist invalide ou introuvable."}), 400
        wlpath = custom_wordlist
    else:
        wlpath = _resolve_wordlist_file(wordlist)
        if not wlpath:
            return jsonify({"error": f"Wordlist '{wordlist}' indisponible sur ce système."}), 400

    import tempfile
    jobdir = tempfile.mkdtemp(prefix="john_")
    hashfile = os.path.join(jobdir, "hashes.txt")
    potfile  = os.path.join(jobdir, "john.pot")
    logfile  = os.path.join(jobdir, "john.log")
    with open(hashfile, "w") as f:
        f.write(hashes + "\n")

    cmd = [_john_bin(), f"--wordlist={wlpath}", f"--pot={potfile}",
           f"--session={os.path.join(jobdir, 'sess')}"]
    if JOHN_FORMATS[fmt]:
        cmd.append(f"--format={JOHN_FORMATS[fmt]}")
    if JOHN_RULES[rules]:
        cmd.append(f"--rules={JOHN_RULES[rules]}")
    cmd.append(hashfile)

    job_id = "JOHN-" + str(uuid.uuid4())[:8].upper()
    logf = open(logfile, "wb")
    proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
    JOHN_JOBS[job_id] = {"proc": proc, "dir": jobdir, "hashfile": hashfile,
                         "potfile": potfile, "logfile": logfile, "logf": logf,
                         "fmt": fmt, "started": time.time(), "cmd": " ".join(cmd),
                         "operator": get_current_user(), "report_done": False}
    audit("JOHN_START", details=f"job={job_id} format={fmt} rules={rules} wordlist={os.path.basename(wlpath)}")
    return jsonify({"ok": True, "job_id": job_id, "command": " ".join(cmd)})

@app.route("/api/john/status/<job_id>")
@require_auth
def john_status(job_id):
    job = JOHN_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job introuvable"}), 404
    proc = job["proc"]
    running = proc.poll() is None
    # Identifiants déchiffrés (lit le .pot via --show) — incrémental.
    creds = []
    try:
        show_cmd = [_john_bin(), "--show", f"--pot={job['potfile']}"]
        if JOHN_FORMATS.get(job["fmt"]):
            show_cmd.append(f"--format={JOHN_FORMATS[job['fmt']]}")
        show_cmd.append(job["hashfile"])
        out = subprocess.run(show_cmd, capture_output=True, text=True, timeout=10)
        creds = _john_parse_show(out.stdout)
    except Exception:
        pass
    # Tail du log (statut live de john).
    log_tail = ""
    try:
        with open(job["logfile"], "r", errors="replace") as f:
            log_tail = f.read()[-4000:]
    except Exception:
        pass
    # Auto-rapport : UNE seule fois, à la fin du job ET seulement si des hash ont
    # été cassés (sinon pas de findings -> pas de rapport). report_done évite les
    # doublons puisque /status est sondé en boucle.
    report_id = None
    if (not running) and creds and not job.get("report_done"):
        vulns = [{"severity": "high", "name": f"Hash cassé : {(c.get('user') or '(hash)')} / {c.get('password','')}",
                  "module": "John the Ripper", "port": "", "cve": "N/A",
                  "recommendation": "Imposer des mots de passe forts et un hachage robuste (bcrypt/argon2)."}
                 for c in creds[:50]]
        report_id = _maybe_auto_report("john", "hashes (" + job["fmt"] + ")",
                                       log_tail, ["John the Ripper"],
                                       vulnerabilities=vulns, operator=job.get("operator"))
        job["report_done"] = True
    return jsonify({"ok": True, "running": running, "done": not running,
                    "cracked": creds, "log": log_tail, "report_id": report_id,
                    "elapsed": round(time.time() - job["started"], 1),
                    "command": job.get("cmd", "")})

@app.route("/api/john/stop/<job_id>", methods=["POST"])
@require_auth
def john_stop(job_id):
    job = JOHN_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job introuvable"}), 404
    proc = job["proc"]
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        job["logf"].close()
    except Exception:
        pass
    audit("JOHN_STOP", details=f"job={job_id}")
    return jsonify({"ok": True, "message": "Cracking arrêté"})


# ── SESSIONS POST-EXPLOITATION (Metasploit RPC) ───────────────────────────────
# Gère les sessions Metasploit ACTIVES (ouvertes via la page Metasploit / un
# module exploit comme vsftpd_234_backdoor) : liste, exécution de commandes,
# arrêt. Faisabilité validée empiriquement (Phase A) : sessions.list expose les
# métadonnées, write()/read() exécute des commandes shell, stop() ferme la
# session. Cette page n'OUVRE PAS d'exploit elle-même (l'utilisateur déclenche
# l'ouverture depuis la page Metasploit) — uniquement de la gestion.
def _detect_lhost(target=None):
    """IP locale que l'OS utiliserait pour joindre la cible (ou une cible
    publique par défaut) — sert de LHOST par défaut pour les payloads à callback.
    N'envoie aucun paquet (socket UDP non connecté réellement)."""
    probe = target or "8.8.8.8"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return ""

@app.route("/api/lhost")
@require_auth
def api_lhost():
    return jsonify({"lhost": _detect_lhost(request.args.get("target"))})

@app.route("/api/sessions")
@require_auth
def list_sessions():
    try:
        _msf_probe(timeout=8)
        client = _msf_client()
        raw = client.sessions.list or {}
    except MetasploitError as e:
        return jsonify({"error": str(e), "lhost": _detect_lhost()}), 503
    except Exception as e:
        return jsonify({"error": f"Erreur RPC: {e}", "lhost": _detect_lhost()}), 503
    # Isolation par utilisateur (BUG 6) : un analyste ne voit que les sessions
    # qu'il a ouvertes via PenToolbox ; l'admin les voit toutes.
    user, role = get_current_user(), get_current_role()
    sessions = []
    for sid, info in raw.items():
        if not _can_access_session(sid, user, role):
            continue
        sessions.append({
            "id": str(sid),
            "type": info.get("type", ""),
            "target": info.get("session_host") or info.get("target_host") or "",
            "tunnel_peer": info.get("tunnel_peer", ""),
            "via_exploit": info.get("via_exploit", ""),
            "via_payload": info.get("via_payload", ""),
            "info": info.get("info", ""),
            "username": info.get("username", ""),
            "arch": info.get("arch", ""),
            "owner": _session_owner(sid) or "",
        })
    return jsonify({"ok": True, "sessions": sessions, "lhost": _detect_lhost()})

@app.route("/api/sessions/<sid>/exec", methods=["POST"])
@require_auth
def session_exec(sid):
    """Exécute une commande dans une session shell/meterpreter (write + read).
    Isolation par utilisateur (BUG 6) : un analyste ne peut interagir qu'avec
    SES propres sessions (celles qu'il a ouvertes via PenToolbox) ; l'admin avec
    toutes. C'est un assouplissement délibéré de l'ancienne règle « admin
    uniquement » : un analyste est un opérateur pentest à part entière sur son
    propre travail, mais ne touche jamais aux sessions d'autrui."""
    if not _can_access_session(sid):
        audit("SESSION_EXEC_DENIED", details=f"sid={sid}")
        return jsonify({"error": "Session non autorisée"}), 403
    data = request.json or {}
    cmd = (data.get("command", "") or "").strip()
    if not cmd:
        return jsonify({"error": "Commande vide"}), 400
    try:
        _msf_probe(timeout=8)
        client = _msf_client()
        raw = client.sessions.list or {}
        if str(sid) not in {str(k) for k in raw.keys()}:
            return jsonify({"error": "Session introuvable"}), 404
        sess = client.sessions.session(sid)
        stype = raw.get(sid, raw.get(str(sid), {})).get("type", "shell")
        audit("SESSION_EXEC", details=f"sid={sid} type={stype} cmd={cmd[:120]}")
        if stype == "meterpreter":
            # meterpreter : run_with_output lit jusqu'à end_strs ou expiration.
            output = sess.run_with_output(cmd, ["\n"], timeout=20)
        else:
            # Shell : la sortie arrive de façon asynchrone et le buffer est drainé
            # par la 1re lecture -> on POLL et on accumule (une lecture unique à
            # délai fixe rate la sortie de façon non déterministe). On s'arrête dès
            # qu'on a reçu des données suivies d'un tick silencieux (commande finie).
            try:
                sess.read()  # vide le buffer en attente
            except Exception:
                pass
            sess.write(cmd + "\n")
            output = ""
            for _ in range(12):
                time.sleep(1)
                chunk = sess.read() or ""
                output += chunk
                if output.strip() and not chunk:
                    break
    except MetasploitError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Erreur RPC: {e}"}), 500
    return jsonify({"ok": True, "output": output or "(pas de sortie)"})

@app.route("/api/sessions/<sid>/kill", methods=["POST"])
@require_auth
def session_kill(sid):
    """Ferme une session. Isolation par utilisateur (BUG 6) : un analyste ne
    peut tuer que SES sessions ; l'admin n'importe laquelle."""
    if not _can_access_session(sid):
        audit("SESSION_KILL_DENIED", details=f"sid={sid}")
        return jsonify({"error": "Session non autorisée"}), 403
    try:
        _msf_probe(timeout=8)
        client = _msf_client()
        raw = client.sessions.list or {}
        if str(sid) not in {str(k) for k in raw.keys()}:
            return jsonify({"error": "Session introuvable"}), 404
        client.sessions.session(sid).stop()
        with SESSION_OWNERS_LOCK:
            SESSION_OWNERS.pop(str(sid), None)
        audit("SESSION_KILL", details=f"sid={sid}")
    except MetasploitError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"Erreur RPC: {e}"}), 500
    return jsonify({"ok": True, "message": f"Session {sid} fermée"})

@app.route("/api/hydra/open-session", methods=["POST"])
@require_auth
def hydra_open_session():
    """Ouvre une VRAIE session Metasploit à partir d'identifiants trouvés par
    Hydra (Improvement 2). SSH -> auxiliary/scanner/ssh/ssh_login (ouvre une
    session shell pour chaque login valide). La session apparaît ensuite dans la
    page Sessions, isolée par utilisateur (SESSION_OWNERS). Déclenchement
    EXPLICITE côté UI (bouton « Ouvrir une session »), jamais automatique.
    Comme elle accorde un shell, la cible passe le MÊME contrôle de périmètre que
    les exploits (ALLOWED_EXPLOIT_SUBNETS) et la validation _is_safe_scan_target.
    SMB : non couvert ici de façon fiable (psexec vise Windows ; la cible labo
    Metasploitable est un Samba Linux) -> renvoyé en erreur explicite plutôt que
    de prétendre le supporter."""
    data = request.json or {}
    target = (data.get("target", "") or "").strip()
    service = (data.get("service", "") or "").strip().lower()
    username = (data.get("username", "") or "").strip()
    password = data.get("password", "") or ""
    port = str(data.get("port", "") or "").strip()
    if not target or not username:
        return jsonify({"error": "Cible et identifiant requis"}), 400
    if not _is_safe_scan_target(target):
        return jsonify({"error": "Cible invalide"}), 400
    if not _target_in_allowed_exploit_subnets(target):
        audit("HYDRA_SESSION_TARGET_REJECTED", details=f"target={target}")
        return jsonify({"error": "Cible hors du périmètre labo autorisé (ALLOWED_EXPLOIT_SUBNETS)"}), 403
    if service != "ssh":
        return jsonify({"error": f"Ouverture de session non supportée pour « {service} » "
                                 "(SSH uniquement ; le brute SMB reste sur la page Hydra/Metasploit)"}), 400
    try:
        _msf_probe(timeout=10)
        client = _msf_client()
    except MetasploitError as e:
        return jsonify({"error": str(e)}), 503

    user = get_current_user()
    console = None
    try:
        sessions_before = set((client.sessions.list or {}).keys())
        mod = client.modules.use("auxiliary", "scanner/ssh/ssh_login")
        mod["RHOSTS"] = target
        if port.isdigit():
            mod["RPORT"] = int(port)
        mod["USERNAME"] = username
        mod["PASSWORD"] = password
        mod["BLANK_PASSWORDS"] = (password == "")
        mod["STOP_ON_SUCCESS"] = True
        console = client.consoles.console()
        output = console.run_module_with_output(mod, timeout=MSF_MAX_RUNTIME)
        opened = _msf_detect_new_sessions(client, sessions_before, target)
        for sid, _info in opened:
            _record_session_owner(sid, user)
        audit("HYDRA_OPEN_SESSION", user=user,
              details=f"target={target} service={service} login={username} sessions={len(opened)}")
        if opened:
            sid = str(opened[0][0])
            return jsonify({"ok": True, "session_id": sid, "output": output,
                            "message": f"Session #{sid} ouverte sur {target}"})
        return jsonify({"ok": False, "output": output,
                        "error": "Identifiants rejetés ou aucune session créée (service injoignable ?)"})
    except Exception as e:
        return jsonify({"error": f"Erreur RPC: {e}"}), 500
    finally:
        if console is not None:
            try: console.destroy()
            except Exception: pass


# ── RAPPORTS (avec chiffrement Fernet) ────────────────────────────────────────
def _save_scan_report(target, vulnerabilities=None, dns_data=None, scan_output="",
                       modules_run=None, operator=None, auto=False):
    """
    Construit et persiste un rapport chiffre (reports/<id>.enc), meme schema
    que la route /api/report/generate ci-dessous. Factorise ici pour que les
    scans (Nmap, DNSDumpster, OpenVAS) puissent sauvegarder un rapport
    automatiquement a la fin d'un scan reussi, sans attendre le flux manuel
    "Exploitation auto" -> "Generer un rapport" -> cf. CLAUDE.md "Reporting":
    avant ce changement les resultats ne survivaient qu'en DOM et disparaissaient
    au refresh; ils persistent maintenant via le meme mecanisme que la page
    Rapports (qui relit toujours le disque, jamais un etat en memoire/DOM).

    operator: a fournir explicitement quand appele hors contexte de requete
    Flask (ex: thread de fond _openvas_worker) car get_current_user() y leve
    une RuntimeError (pas de `session`/`g` disponibles dans un thread).
    """
    report_id = "RPT-" + str(uuid.uuid4())[:8].upper()
    vulnerabilities = vulnerabilities or []
    report = {
        "id": report_id,
        "target": target,
        "operator": operator or get_current_user(),
        "date": datetime.datetime.now().isoformat(),
        "date_display": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
        "expiry": (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%d/%m/%Y"),
        "vulnerabilities": vulnerabilities,
        "dns_data": dns_data or {},
        "scan_output": scan_output,
        "modules_run": modules_run or [],
        "auto": auto,  # genere automatiquement en fin de scan, vs manuellement via Exploitation
    }
    report["stats"] = {
        "critical": sum(1 for v in vulnerabilities if v.get("severity")=="critical"),
        "high":     sum(1 for v in vulnerabilities if v.get("severity")=="high"),
        "medium":   sum(1 for v in vulnerabilities if v.get("severity")=="medium"),
        "low":      sum(1 for v in vulnerabilities if v.get("severity")=="low"),
        "total":    len(vulnerabilities),
    }
    path = os.path.join(REPORTS_DIR, f"{report_id}.enc")
    with open(path, "wb") as f:
        f.write(encrypt_report(report))
    audit("REPORT_GENERATED", user=operator, details=f"report_id={report_id} target={target} auto={auto}")
    return report_id, report

@app.route("/api/report/generate", methods=["POST"])
@require_auth
def generate_report():
    data = request.json
    report_id, report = _save_scan_report(
        target=data.get("target",""),
        vulnerabilities=data.get("vulnerabilities",[]),
        dns_data=data.get("dns_data",{}),
        scan_output=data.get("scan_output",""),
        modules_run=data.get("modules_run",[]),
    )
    return jsonify({"ok": True, "report_id": report_id, "report": report})

@app.route("/api/reports")
@require_auth
def list_reports():
    reports = []
    # Isolation par utilisateur : un analyste ne voit que ses propres rapports,
    # l'admin les voit tous (cf. _can_access_report).
    for fname, r in _iter_reports():
        if not _can_access_report(r):
            continue
        reports.append({"id":r["id"],"target":r["target"],"date_display":r["date_display"],
                         "date":r.get("date",""),
                         "expiry":r["expiry"],"operator":r["operator"],"stats":r.get("stats",{}),
                         "modules_run":r.get("modules_run",[]),"auto":r.get("auto",False)})
    # Tri par date de creation (ISO 8601 -> tri lexicographique = chronologique),
    # le plus recent en tete. L'ancien tri par "id" (UUID aleatoire) placait un
    # rapport tout juste genere a une position arbitraire de la liste: apres une
    # exploitation multi-modules il pouvait se retrouver en bas, donnant
    # l'impression qu'aucun rapport n'avait ete cree (et laissant en tete un
    # autre rapport, souvent mono-module).
    reports.sort(key=lambda x: x.get("date",""), reverse=True)
    return jsonify(reports)

def _get_report(report_id):
    """Renvoie le rapport déchiffré seulement si l'utilisateur courant y a accès
    (son propre rapport, ou tous pour l'admin) — sinon None, ce qui se traduit
    par un 404 côté route : on ne révèle pas l'existence d'un rapport d'autrui."""
    path = os.path.join(REPORTS_DIR, f"{report_id}.enc")
    if not os.path.exists(path): return None
    with open(path, "rb") as f:
        report = decrypt_report(f.read())
    if not _can_access_report(report):
        return None
    return report

@app.route("/api/report/<report_id>/html")
@require_auth
def download_html(report_id):
    r = _get_report(report_id)
    if not r: return "Rapport introuvable", 404
    audit("REPORT_DOWNLOAD", details=f"report_id={report_id} format=html")
    html = render_template("report_template.html", r=r)
    return html, 200, {"Content-Type":"text/html; charset=utf-8","Content-Disposition":f"attachment; filename=rapport_{report_id}.html"}

@app.route("/api/report/<report_id>/json")
@require_auth
def download_json(report_id):
    r = _get_report(report_id)
    if not r: return "Rapport introuvable", 404
    audit("REPORT_DOWNLOAD", details=f"report_id={report_id} format=json")
    content = json.dumps(r, ensure_ascii=False, indent=2)
    return content, 200, {"Content-Type":"application/json","Content-Disposition":f"attachment; filename=rapport_{report_id}.json"}

@app.route("/api/report/<report_id>/csv")
@require_auth
def download_csv(report_id):
    r = _get_report(report_id)
    if not r: return "Rapport introuvable", 404
    audit("REPORT_DOWNLOAD", details=f"report_id={report_id} format=csv")
    lines = [f"# PenToolbox v4.0 — {r['id']} — {r['target']} — {r['date_display']}",
             "ID,Severite,Vulnerabilite,Module,Port,CVE,Recommandation"]
    for i,v in enumerate(r.get("vulnerabilities",[]),1):
        lines.append(f"{i},{v.get('severity','')},\"{v.get('name','')}\",{v.get('module','')},{v.get('port','')},{v.get('cve','N/A')},\"{v.get('recommendation','')}\"")
    return "\n".join(lines), 200, {"Content-Type":"text/csv; charset=utf-8","Content-Disposition":f"attachment; filename=rapport_{report_id}.csv"}

@app.route("/api/report/<report_id>", methods=["DELETE"])
@require_auth
def delete_report(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.enc")
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "Rapport introuvable"}), 404
    # Un analyste ne peut supprimer que ses propres rapports (admin: tous).
    try:
        with open(path, "rb") as f:
            report = decrypt_report(f.read())
    except Exception:
        report = {}
    if not _can_access_report(report):
        return jsonify({"ok": False, "error": "Rapport introuvable"}), 404
    os.remove(path)
    audit("REPORT_DELETED", details=f"report_id={report_id}")
    return jsonify({"ok": True, "reports_count": _count_reports()})

@app.route("/api/reports", methods=["DELETE"])
@require_auth
def delete_all_reports():
    """Suppression en masse des rapports VISIBLES par l'utilisateur courant
    (ses propres rapports ; admin: tous). Renvoie le nouveau compte pour mise à
    jour immédiate des compteurs côté UI."""
    deleted = 0
    for fname, r in list(_iter_reports()):
        if not _can_access_report(r):
            continue
        try:
            os.remove(os.path.join(REPORTS_DIR, fname))
            deleted += 1
        except OSError:
            pass
    audit("REPORTS_DELETED_ALL", details=f"deleted={deleted}")
    return jsonify({"ok": True, "deleted": deleted, "reports_count": _count_reports()})

@app.route("/api/report/<report_id>/pdf")
@require_auth
def download_pdf(report_id):
    r = _get_report(report_id)
    if not r: return "Rapport introuvable", 404
    audit("REPORT_DOWNLOAD", details=f"report_id={report_id} format=pdf")

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    elements = []

    # Titre
    title_style = ParagraphStyle('title', parent=styles['Heading1'],
                                  fontSize=20, textColor=colors.HexColor('#00d4ff'),
                                  spaceAfter=6)
    elements.append(Paragraph("PenToolbox v4.0 — Rapport de Pentest", title_style))

    sub_style = ParagraphStyle('sub', parent=styles['Normal'],
                                fontSize=10, textColor=colors.HexColor('#7a9cc4'),
                                spaceAfter=20)
    elements.append(Paragraph(f"Rapport {r['id']} — {r['date_display']} — Confidentiel", sub_style))
    elements.append(Spacer(1, 0.3*cm))

    # Métadonnées
    meta_data = [
        ['Cible', r['target']],
        ['Opérateur', r['operator']],
        ['Date', r['date_display']],
        ['Expiration', r['expiry']],
        ['Rapport ID', r['id']],
    ]
    stats = r.get('stats', {})
    risk = 'CRITIQUE' if stats.get('critical',0)>0 else 'ÉLEVÉ' if stats.get('high',0)>0 else 'MOYEN' if stats.get('medium',0)>0 else 'FAIBLE'
    meta_data.append(['Niveau de risque', risk])

    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#0f1420')),
        ('BACKGROUND', (1,0), (1,-1), colors.HexColor('#151b2b')),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor('#e8f4ff')),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1e2d4a')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#0f1420'), colors.HexColor('#151b2b')]),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.5*cm))

    # Stats
    sev_colors = {'critical': '#ff4444', 'high': '#ff8c00', 'medium': '#ffd700', 'low': '#00d4ff'}
    stats_data = [['Critiques', 'Élevées', 'Moyennes', 'Faibles', 'Total']]
    stats_data.append([
        str(stats.get('critical',0)), str(stats.get('high',0)),
        str(stats.get('medium',0)), str(stats.get('low',0)), str(stats.get('total',0))
    ])
    stats_table = Table(stats_data, colWidths=[3.4*cm]*5)
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1420')),
        ('TEXTCOLOR', (0,0), (0,0), colors.HexColor('#ff4444')),
        ('TEXTCOLOR', (1,0), (1,0), colors.HexColor('#ff8c00')),
        ('TEXTCOLOR', (2,0), (2,0), colors.HexColor('#ffd700')),
        ('TEXTCOLOR', (3,0), (3,0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (4,0), (4,0), colors.HexColor('#e8f4ff')),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#151b2b')),
        ('TEXTCOLOR', (0,1), (-1,1), colors.HexColor('#e8f4ff')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1e2d4a')),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.5*cm))

    # Tableau vulnérabilités
    heading_style = ParagraphStyle('heading', parent=styles['Heading2'],
                                    fontSize=13, textColor=colors.HexColor('#00d4ff'),
                                    spaceBefore=10, spaceAfter=8)
    elements.append(Paragraph(f"Vulnérabilités détectées ({stats.get('total',0)})", heading_style))

    vuln_data = [['#', 'Sévérité', 'Vulnérabilité', 'Service', 'CVE']]
    sev_map = {'critical': colors.HexColor('#ff4444'), 'high': colors.HexColor('#ff8c00'),
               'medium': colors.HexColor('#ffd700'), 'low': colors.HexColor('#00d4ff')}

    for i, v in enumerate(r.get('vulnerabilities', []), 1):
        vuln_data.append([
            str(i), v.get('severity','').upper(),
            v.get('name','')[:50], f"{v.get('module','')} / {v.get('port','')}",
            v.get('cve','N/A')
        ])

    if len(vuln_data) > 1:
        vuln_table = Table(vuln_data, colWidths=[1*cm, 2.5*cm, 7*cm, 4*cm, 2.5*cm])
        style_cmds = [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f1420')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#7a9cc4')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#1e2d4a')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#0f1420'), colors.HexColor('#151b2b')]),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.HexColor('#e8f4ff')),
        ]
        for i, v in enumerate(r.get('vulnerabilities', []), 1):
            sev = v.get('severity','low')
            c = sev_map.get(sev, colors.white)
            style_cmds.append(('TEXTCOLOR', (1,i), (1,i), c))
        vuln_table.setStyle(TableStyle(style_cmds))
        elements.append(vuln_table)
    else:
        elements.append(Paragraph("Aucune vulnérabilité détectée.", styles['Normal']))

    # Footer
    elements.append(Spacer(1, 1*cm))
    footer_style = ParagraphStyle('footer', parent=styles['Normal'],
                                   fontSize=8, textColor=colors.HexColor('#3d5a7a'))
    elements.append(Paragraph(
        f"PenToolbox v4.0 — Rapport généré le {r['date_display']} — Confidentiel — Usage interne uniquement",
        footer_style))

    doc.build(elements)
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f"rapport_{report_id}.pdf",
                     mimetype='application/pdf')


# ── LANCEMENT ──────────────────────────────────────────────────────────────────
def _ensure_self_signed_cert(base_dir: str) -> tuple[str, str] | None:
    """
    Genere (si absent) un certificat auto-signe pour servir l'UI en HTTPS quand
    l'app tourne hors docker-compose (lancee via python app.py / les .bat/.sh).
    Sous docker-compose, c'est nginx qui termine le TLS (voir nginx/) et Flask
    reste volontairement en HTTP en interne — cette fonction n'est donc jamais
    appelee dans ce cas (cf. garde DOCKER_ENV dans __main__).

    Utilise `cryptography` (deja une dependance, via Fernet) plutot que de
    shell-out vers le binaire openssl, qui n'est pas garanti present sur les
    postes Windows ciblés par les lanceurs .bat.
    """
    cert_path = os.path.join(base_dir, "cert.pem")
    key_path = os.path.join(base_dir, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PenToolbox"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, key_path
    except Exception as e:
        print(f"  [!] Certificat auto-signe non genere ({e}) — retour en HTTP.")
        return None


if __name__ == "__main__":
    import threading, webbrowser, time as _time

    is_docker = bool(os.environ.get("DOCKER_ENV"))
    host = "0.0.0.0" if is_docker else "127.0.0.1"

    ssl_context = None
    # TOUJOURS utiliser HTTPS (certificat auto-signé)
    cert_files = _ensure_self_signed_cert(SECRETS_DIR)
    if cert_files:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(*cert_files)
    scheme = "https" if ssl_context else "http"

    print("=" * 60)
    print("  PenToolbox v4.0 — Demarrage")
    print("=" * 60)
    print(f"  OS           : {platform.system()} {platform.release()}")
    print(f"  Python       : {platform.python_version()}")
    print(f"  Session      : timeout 30 min")
    print(f"  Passwords    : bcrypt")
    print(f"  Rapports     : chiffres Fernet")
    print(f"  Rate limit   : {MAX_ATTEMPTS} tentatives / {WINDOW}s → blocage {BLOCK_DURATION}s")
    print(f"  Audit log    : {AUDIT_FILE}")
    for t in ["nmap","dig","nikto","sqlmap","hydra","enum4linux-ng"]:
        print(f"  {t:<12} : {'OK' if is_tool_available(t) else 'absent'}")
    print("=" * 60)
    print(f"  Interface    : {scheme}://localhost:5000")
    print("=" * 60)

    audit("SERVER_START", user="system", details=f"os={platform.system()}")

    def open_browser():
        _time.sleep(1.5)
        webbrowser.open(f"{scheme}://localhost:5000")
    threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=host, port=5000, debug=False, use_reloader=False, ssl_context=ssl_context)
