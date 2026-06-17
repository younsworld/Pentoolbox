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
import subprocess, socket, json, os, uuid, datetime, platform, shutil, re, secrets, bcrypt, time

app = Flask(__name__)

# ── SECRET KEY unique par poste ───────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_FILE = os.path.join(BASE_DIR, ".secret_key")
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(app.secret_key)
    print("  [+] Secret key generee -> .secret_key")

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)

CORS(app, supports_credentials=True, origins=[
    "http://localhost:5000", "http://127.0.0.1:5000",
    "http://localhost", "http://127.0.0.1"
])

REPORTS_DIR = os.path.join(BASE_DIR, "reports")
USERS_FILE  = os.path.join(BASE_DIR, ".users")
AUDIT_FILE  = os.path.join(BASE_DIR, "audit.log")
FERNET_FILE = os.path.join(BASE_DIR, ".fernet_key")
os.makedirs(REPORTS_DIR, exist_ok=True)

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
    ip  = request.remote_addr if request else "system"
    u   = user or session.get("user", "unknown")
    line = f"[{now}] {action:<22} user={u:<15} ip={ip:<15} {details}\n"
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except:
        pass
    print(f"  [AUDIT] {line.strip()}")

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
    tools = {t: is_tool_available(t) for t in ["nmap","dig","host","whois","arp-scan","nslookup","curl","hydra","nikto","sqlmap"]}
    return jsonify({
        "os": platform.system(), "python": platform.python_version(),
        "tools": tools, "reports_count": len(os.listdir(REPORTS_DIR)),
    })

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
    # Un user peut changer son propre mdp, seul admin peut changer celui des autres
    if current_user != "admin" and current_user != username:
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
    if not os.path.exists(AUDIT_FILE):
        return jsonify({"lines": []})
    with open(AUDIT_FILE, encoding="utf-8") as f:
        lines = f.readlines()
    return jsonify({"lines": [l.strip() for l in lines[-200:]]})  # 200 dernières lignes

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
    return jsonify(results)

# ── NMAP ───────────────────────────────────────────────────────────────────────
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
    audit("NMAP_SCAN", details=f"target={target} type={stype}")
    cmds = {
        "default": f"nmap -sV -sC -T4 --open {target}",
        "quick":   f"nmap -T4 -F {target}",
        "full":    f"nmap -sV -sC -O -T4 -A --open {target}",
        "udp":     f"nmap -sU -T4 --top-ports 100 {target}",
        "vuln":    f"nmap -sV --script vuln -T4 {target}",
        "stealth": f"nmap -sS -T2 -f {target}",
    }
    start = time.time()
    output = run_cmd(cmds.get(stype, cmds["default"]), timeout=300)
    elapsed = round(time.time()-start, 2)
    return jsonify({"target": target, "command": cmds.get(stype, cmds["default"]), "output": output, "elapsed": elapsed})

# ── ARP ────────────────────────────────────────────────────────────────────────
@app.route("/api/arp", methods=["POST"])
@require_auth
def arp_scan():
    target = request.json.get("range","192.168.1.0/24").strip()
    audit("ARP_SCAN", details=f"range={target}")
    start_arp = time.time()

    if platform.system() == "Windows":
        base = ".".join(target.split(".")[:3]) if "/" in target else target
        ps_script = [
            "$b='" + base + "';",
            "$r=1..254|%{",
            "$ip=\"$b.$_\";",
            "$p=New-Object Net.NetworkInformation.Ping;",
            "try{$x=$p.Send($ip,500);",
            "if($x.Status -eq 'Success'){",
            "try{$h=[Net.Dns]::GetHostEntry($ip).HostName}catch{$h='?'};",
            "Write-Host ('[+] '+$ip.PadRight(18)+' '+$x.RoundtripTime+'ms  '+$h)",
            "}}catch{}}|?{$_}|sort"
        ]
        ps_one = " ".join(ps_script)
        output = run_cmd('powershell -NoProfile -ExecutionPolicy Bypass -Command "' + ps_one + '"', timeout=120)
        elapsed_arp = round(time.time()-start_arp, 2)
        output = "[*] ARP Scan Windows (PowerShell) -> " + target + "\n[*] Duree: " + str(elapsed_arp) + "s\n\n" + output

    elif is_tool_available("nmap"):
        output = run_cmd(f"nmap -sn {target}", timeout=120)
        elapsed_arp = round(time.time()-start_arp, 2)
        output = f"[*] Scan réseau → {target}\n[*] Commande: nmap -sn {target}\n[*] Durée: {elapsed_arp}s\n\n" + output

    elif is_tool_available("arp-scan"):
        output = run_cmd(f"arp-scan {target}", timeout=120)
        elapsed_arp = round(time.time()-start_arp, 2)
    else:
        output = "[!] Aucun outil disponible."
        elapsed_arp = 0
    return jsonify({"range": target, "output": output})

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
    return jsonify({"target": target, "output": out, "elapsed": elapsed})

# ── SQLMAP ─────────────────────────────────────────────────────────────────────
@app.route("/api/sqlmap", methods=["POST"])
@require_auth
def sqlmap_scan():
    target = request.json.get("target","").strip()
    if not target: return jsonify({"error":"URL requise"}), 400
    if not is_tool_available("sqlmap"): return jsonify({"error":"SQLMap non installe","install":"pip install sqlmap"}), 400
    audit("SQLMAP_SCAN", details=f"target={target}")
    start = time.time()
    out = run_cmd(f'sqlmap -u "{target}" --batch --level=1 --risk=1 --banner 2>&1 | head -60', timeout=120)
    elapsed = round(time.time()-start,2)
    return jsonify({"target": target, "output": out, "elapsed": elapsed})


# ── HYDRA ──────────────────────────────────────────────────────────────────────
@app.route("/api/hydra", methods=["POST"])
@require_auth
def hydra_scan():
    data     = request.json
    target   = data.get("target", "").strip()
    service  = data.get("service", "ssh")
    username = data.get("username", "admin")
    wordlist = data.get("wordlist", "common")
    if not target:
        return jsonify({"error": "Cible requise"}), 400
    if not is_tool_available("hydra"):
        return jsonify({"error": "Hydra non installe", "install": "sudo apt install hydra"}), 400

    audit("HYDRA_SCAN", details=f"target={target} service={service}")

    # Wordlists intégrées
    wordlists = {
        "common": ["admin","password","123456","root","toor","pass","test","guest","admin123","password123"],
        "ssh":    ["root","admin","ubuntu","pi","user","test","guest"],
        "ftp":    ["anonymous","admin","ftp","user","root","test"],
    }
    wl = wordlists.get(wordlist, wordlists["common"])

    # Crée un fichier wordlist temporaire
    import tempfile
    wf = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    wf.write('\n'.join(wl))
    wf.close()

    try:
        cmd = f"hydra -l {username} -P {wf.name} -t 4 -f {service}://{target}"
        start_time = time.time()
        output = run_cmd(cmd, timeout=120)
        elapsed = round(time.time() - start_time, 2)
        output = f"[*] Commande: {cmd}\n[*] Duree: {elapsed}s\n\n" + output
    finally:
        os.unlink(wf.name)

    return jsonify({"target": target, "service": service, "output": output, "elapsed": elapsed})


# ── ARP WINDOWS (reçoit les résultats du script PowerShell local) ─────────────
arp_results_cache = {}

@app.route("/api/arp/windows_results", methods=["POST"])
def arp_windows_results():
    """Reçoit les résultats du scan ARP depuis le script PowerShell Windows."""
    data = request.json
    scan_id = data.get("scan_id", "default")
    arp_results_cache[scan_id] = {
        "output": data.get("output", ""),
        "done": True,
        "timestamp": time.time()
    }
    return jsonify({"ok": True})

@app.route("/api/arp/poll/<scan_id>")
@require_auth
def arp_poll(scan_id):
    """Vérifie si les résultats ARP sont disponibles."""
    result = arp_results_cache.get(scan_id)
    if result and result.get("done"):
        del arp_results_cache[scan_id]
        return jsonify({"done": True, "output": result["output"]})
    return jsonify({"done": False})

# ── RAPPORTS (avec chiffrement Fernet) ────────────────────────────────────────
@app.route("/api/report/generate", methods=["POST"])
@require_auth
def generate_report():
    data      = request.json
    report_id = "RPT-" + str(uuid.uuid4())[:8].upper()
    report = {
        "id": report_id,
        "target": data.get("target",""),
        "operator": get_current_user(),
        "date": datetime.datetime.now().isoformat(),
        "date_display": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
        "expiry": (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%d/%m/%Y"),
        "vulnerabilities": data.get("vulnerabilities",[]),
        "dns_data": data.get("dns_data",{}),
        "scan_output": data.get("scan_output",""),
        "modules_run": data.get("modules_run",[]),
    }
    vulns = report["vulnerabilities"]
    report["stats"] = {
        "critical": sum(1 for v in vulns if v.get("severity")=="critical"),
        "high":     sum(1 for v in vulns if v.get("severity")=="high"),
        "medium":   sum(1 for v in vulns if v.get("severity")=="medium"),
        "low":      sum(1 for v in vulns if v.get("severity")=="low"),
        "total":    len(vulns),
    }
    # Sauvegarde chiffree
    path = os.path.join(REPORTS_DIR, f"{report_id}.enc")
    with open(path, "wb") as f:
        f.write(encrypt_report(report))
    audit("REPORT_GENERATED", details=f"report_id={report_id} target={report['target']}")
    return jsonify({"ok": True, "report_id": report_id, "report": report})

@app.route("/api/reports")
@require_auth
def list_reports():
    reports = []
    for fname in os.listdir(REPORTS_DIR):
        if fname.endswith(".enc"):
            try:
                with open(os.path.join(REPORTS_DIR, fname), "rb") as f:
                    r = decrypt_report(f.read())
                reports.append({"id":r["id"],"target":r["target"],"date_display":r["date_display"],
                                 "expiry":r["expiry"],"operator":r["operator"],"stats":r.get("stats",{})})
            except: pass
    reports.sort(key=lambda x: x["id"], reverse=True)
    return jsonify(reports)

def _get_report(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.enc")
    if not os.path.exists(path): return None
    with open(path, "rb") as f:
        return decrypt_report(f.read())

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
    if os.path.exists(path): os.remove(path)
    audit("REPORT_DELETED", details=f"report_id={report_id}")
    return jsonify({"ok": True})

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
# HTTPS supprime - HTTP uniquement pour la stabilite

if __name__ == "__main__":
    import threading, webbrowser, time as _time

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
    for t in ["nmap","dig","arp-scan","nikto","sqlmap"]:
        print(f"  {t:<12} : {'OK' if is_tool_available(t) else 'absent'}")
    print("=" * 60)
    print("  Interface    : http://localhost:5000")
    print("  Login        : admin / pentest2025")
    print("=" * 60)

    audit("SERVER_START", user="system", details=f"os={platform.system()}")

    def open_browser():
        _time.sleep(1.5)
        # Ouvre en HTTPS si pas Docker
        url = "http://localhost:5000"
        webbrowser.open(url)
    threading.Thread(target=open_browser, daemon=True).start()

    host = "0.0.0.0" if os.environ.get("DOCKER_ENV") else "127.0.0.1"

    ssl_context = None
    print("  HTTP        : http://localhost:5000")
    
    app.run(host=host, port=5000, debug=False, use_reloader=False, ssl_context=ssl_context)
