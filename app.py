"""
PenToolbox v4.0 — Application Flask
Lance avec : python app.py
Interface : http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify, session, send_file
from flask_cors import CORS
import subprocess
import socket
import json
import os
import uuid
import datetime
import platform
import shutil
import re

app = Flask(__name__)
app.secret_key = "pentoolbox_secret_2025_change_me"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
CORS(app, supports_credentials=True, origins=["http://localhost:5000", "http://127.0.0.1:5000", "http://localhost", "http://127.0.0.1"])

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ─── Comptes utilisateurs (simple, à remplacer par DB en prod) ───────────────
USERS = {
    "admin": "pentest2025",
    "analyst": "analyst2025",
}

# ─── Utilitaires ─────────────────────────────────────────────────────────────
def is_tool_available(tool):
    return shutil.which(tool) is not None

def run_cmd(cmd, timeout=60):
    """Exécute une commande shell et retourne stdout + stderr."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[!] Timeout après {timeout}s"
    except Exception as e:
        return f"[!] Erreur: {str(e)}"

# ─── Auth ─────────────────────────────────────────────────────────────────────
# Token simple en mémoire (pas de session cookie)
ACTIVE_TOKENS = {}

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        if not data:
            return jsonify({"ok": False, "error": "Requete invalide — pas de JSON"}), 400
        u = data.get("username", "").strip()
        p = data.get("password", "")
        print(f"  [LOGIN] Tentative: user='{u}'")
        if USERS.get(u) == p:
            import secrets
            token = secrets.token_hex(32)
            ACTIVE_TOKENS[token] = u
            session["user"] = u
            print(f"  [LOGIN] Succes: {u} — token={token[:8]}...")
            resp = jsonify({"ok": True, "user": u, "token": token})
            resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            return resp
        print(f"  [LOGIN] Echec: user='{u}' — mauvais mot de passe")
        return jsonify({"ok": False, "error": "Identifiants incorrects"}), 401
    except Exception as e:
        print(f"  [LOGIN] Erreur: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    try:
        # Remove token if provided
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            ACTIVE_TOKENS.pop(token, None)
        session.clear()
    except:
        pass
    return jsonify({"ok": True})

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # Vérifie le token dans le header Authorization
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token in ACTIVE_TOKENS:
                return f(*args, **kwargs)
        # Vérifie la session Flask classique
        if "user" in session:
            return f(*args, **kwargs)
        return jsonify({"error": "Non authentifié"}), 401
    return decorated

# ─── Page principale ──────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ─── Status système ───────────────────────────────────────────────────────────
@app.route("/api/status")
@require_auth
def status():
    tools = {
        "nmap": is_tool_available("nmap"),
        "dig": is_tool_available("dig"),
        "host": is_tool_available("host"),
        "whois": is_tool_available("whois"),
        "arp-scan": is_tool_available("arp-scan"),
        "nslookup": is_tool_available("nslookup"),
        "curl": is_tool_available("curl"),
        "hydra": is_tool_available("hydra"),
        "nikto": is_tool_available("nikto"),
        "sqlmap": is_tool_available("sqlmap"),
    }
    return jsonify({
        "os": platform.system(),
        "python": platform.python_version(),
        "tools": tools,
        "reports_count": len(os.listdir(REPORTS_DIR)),
    })

# ─── DNSDumpster (vraies données via dig / nslookup) ─────────────────────────
@app.route("/api/dnsdumpster", methods=["POST"])
@require_auth
def dnsdumpster():
    domain = request.json.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domaine requis"}), 400

    # Nettoyage du domaine
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    
    results = {"domain": domain, "a": [], "mx": [], "ns": [], "txt": [], "log": []}
    log = results["log"]

    log.append(f"[*] DNSDumpster — Cible: {domain}")
    log.append(f"[*] Heure: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.append("─" * 56)

    # === Enregistrements A (sous-domaines courants) ===
    log.append("[*] Résolution enregistrements A / sous-domaines...")
    
    common_subs = [
        "www", "mail", "smtp", "pop", "imap", "ftp", "ns1", "ns2",
        "dev", "staging", "api", "admin", "portal", "webmail", "vpn",
        "cdn", "static", "assets", "blog", "shop", "store", "m", "mobile",
        "app", "secure", "login", "intranet", "git", "gitlab", "jenkins",
        "jira", "confluence", "remote", "owa", "exchange", "autodiscover",
    ]
    
    for sub in common_subs:
        hostname = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            results["a"].append({"host": hostname, "ip": ip})
            log.append(f"[+] {ip:<20} {hostname}")
        except socket.gaierror:
            pass

    # Essai dig si disponible (plus complet)
    if is_tool_available("dig"):
        log.append("[*] Exécution dig pour enregistrements MX, NS, TXT...")

        # MX
        mx_out = run_cmd(f"dig MX {domain} +short", timeout=15)
        for line in mx_out.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith(";"):
                parts = line.split()
                prio = parts[0] if len(parts) >= 2 else "?"
                host = parts[1].rstrip(".") if len(parts) >= 2 else parts[0]
                try:
                    ip = socket.gethostbyname(host)
                except:
                    ip = "?"
                results["mx"].append({"host": host, "ip": ip, "priority": prio})
                log.append(f"[MX] {ip:<20} {host}  prio:{prio}")

        # NS
        ns_out = run_cmd(f"dig NS {domain} +short", timeout=15)
        for line in ns_out.strip().split("\n"):
            line = line.strip().rstrip(".")
            if line and not line.startswith(";"):
                try:
                    ip = socket.gethostbyname(line)
                except:
                    ip = "?"
                results["ns"].append({"host": line, "ip": ip})
                log.append(f"[NS] {ip:<20} {line}")

        # TXT
        txt_out = run_cmd(f"dig TXT {domain} +short", timeout=15)
        for line in txt_out.strip().split("\n"):
            line = line.strip().strip('"')
            if line and not line.startswith(";"):
                results["txt"].append(line)
                log.append(f"[TXT] {line}")

    elif is_tool_available("nslookup"):
        log.append("[*] dig absent — utilisation de nslookup...")
        # MX
        mx_out = run_cmd(f"nslookup -type=MX {domain}", timeout=15)
        for line in mx_out.split("\n"):
            if "mail exchanger" in line.lower():
                parts = line.split("=")[-1].strip().split()
                if parts:
                    host = parts[-1].rstrip(".")
                    prio = parts[0] if len(parts) > 1 else "?"
                    try:
                        ip = socket.gethostbyname(host)
                    except:
                        ip = "?"
                    results["mx"].append({"host": host, "ip": ip, "priority": prio})
                    log.append(f"[MX] {ip:<20} {host}  prio:{prio}")

        # NS
        ns_out = run_cmd(f"nslookup -type=NS {domain}", timeout=15)
        for line in ns_out.split("\n"):
            if "nameserver" in line.lower():
                host = line.split("=")[-1].strip().rstrip(".")
                if host:
                    try:
                        ip = socket.gethostbyname(host)
                    except:
                        ip = "?"
                    results["ns"].append({"host": host, "ip": ip})
                    log.append(f"[NS] {ip:<20} {host}")
    else:
        log.append("[~] dig et nslookup absents — installe dnsutils : sudo apt install dnsutils")
        # Fallback Python socket pour MX
        try:
            import dns.resolver
            for rtype in ["MX", "NS", "TXT"]:
                try:
                    ans = dns.resolver.resolve(domain, rtype)
                    for r in ans:
                        if rtype == "MX":
                            h = str(r.exchange).rstrip(".")
                            try: ip = socket.gethostbyname(h)
                            except: ip = "?"
                            results["mx"].append({"host": h, "ip": ip, "priority": str(r.preference)})
                            log.append(f"[MX] {ip:<20} {h}")
                        elif rtype == "NS":
                            h = str(r).rstrip(".")
                            try: ip = socket.gethostbyname(h)
                            except: ip = "?"
                            results["ns"].append({"host": h, "ip": ip})
                            log.append(f"[NS] {ip:<20} {h}")
                        elif rtype == "TXT":
                            t = str(r).strip('"')
                            results["txt"].append(t)
                            log.append(f"[TXT] {t}")
                except: pass
        except ImportError:
            log.append("[~] dnspython absent — lance: pip install dnspython")

    # Résumé
    log.append("─" * 56)
    log.append(f"[✓] Terminé — {len(results['a'])} sous-domaines, {len(results['mx'])} MX, {len(results['ns'])} NS")
    
    return jsonify(results)

# ─── Scan Nmap ────────────────────────────────────────────────────────────────
@app.route("/api/nmap", methods=["POST"])
@require_auth
def nmap_scan():
    data = request.json
    target = data.get("target", "").strip()
    scan_type = data.get("type", "default")
    
    if not target:
        return jsonify({"error": "Cible requise"}), 400

    if not is_tool_available("nmap"):
        if platform.system() == "Windows":
            msg = "[!] Nmap non trouve.\n"
            msg += "    1. Telecharge : https://nmap.org/download.html\n"
            msg += "    2. Installe nmap-X.XX-setup.exe (coche Add to PATH)\n"
            msg += "    3. Ferme et relance app.py\n"
            msg += "    Note: relance CMD en admin si Nmap reste introuvable"
        else:
            msg = "[!] Nmap non installe. Installe avec: sudo apt install nmap"
        return jsonify({"error": "Nmap non installe", "output": msg}), 400

    # Commandes nmap selon le type
    cmds = {
        "default": f"nmap -sV -sC -T4 --open {target}",
        "quick":   f"nmap -T4 -F {target}",
        "full":    f"nmap -sV -sC -O -T4 -A --open {target}",
        "udp":     f"nmap -sU -T4 --top-ports 100 {target}",
        "vuln":    f"nmap -sV --script vuln -T4 {target}",
        "stealth": f"nmap -sS -T2 -f {target}",
    }
    cmd = cmds.get(scan_type, cmds["default"])
    
    output = run_cmd(cmd, timeout=300)
    return jsonify({"target": target, "command": cmd, "output": output})

# ─── ARP Scan ─────────────────────────────────────────────────────────────────
@app.route("/api/arp", methods=["POST"])
@require_auth
def arp_scan():
    target = request.json.get("range", "192.168.1.0/24").strip()
    
    if is_tool_available("arp-scan"):
        cmd = f"arp-scan --localnet {target}"
        output = run_cmd(cmd, timeout=60)
    elif is_tool_available("nmap"):
        cmd = f"nmap -sn {target}"
        output = run_cmd(cmd, timeout=60)
    else:
        output = "[!] arp-scan et nmap absents.\n"
        output += "    Installe: sudo apt install arp-scan nmap"
    
    return jsonify({"range": target, "output": output})

# ─── DNS Lookup ──────────────────────────────────────────────────────────────
@app.route("/api/dns", methods=["POST"])
@require_auth
def dns_lookup():
    data = request.json
    target = data.get("target", "").strip()
    rtype = data.get("type", "A")
    
    if not target:
        return jsonify({"error": "Cible requise"}), 400

    if is_tool_available("dig"):
        output = run_cmd(f"dig {rtype} {target}", timeout=15)
    elif is_tool_available("nslookup"):
        output = run_cmd(f"nslookup -type={rtype} {target}", timeout=15)
    else:
        # Fallback Python
        try:
            ips = socket.getaddrinfo(target, None)
            output = f"; DNS Lookup (Python socket)\n"
            for ip in ips:
                output += f"{target}  {rtype}  {ip[4][0]}\n"
        except Exception as e:
            output = f"[!] Erreur: {e}"
    
    return jsonify({"target": target, "type": rtype, "output": output})

# ─── Nikto (scan web) ─────────────────────────────────────────────────────────
@app.route("/api/nikto", methods=["POST"])
@require_auth
def nikto_scan():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "Cible requise"}), 400
    
    if not is_tool_available("nikto"):
        return jsonify({"error": "Nikto non installé", "install": "sudo apt install nikto"}), 400
    
    if not target.startswith("http"):
        target = "http://" + target
    
    output = run_cmd(f"nikto -h {target} -nointeractive", timeout=120)
    return jsonify({"target": target, "output": output})

# ─── SQLMap ──────────────────────────────────────────────────────────────────
@app.route("/api/sqlmap", methods=["POST"])
@require_auth
def sqlmap_scan():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "URL requise"}), 400
    
    if not is_tool_available("sqlmap"):
        return jsonify({"error": "SQLMap non installé", "install": "sudo apt install sqlmap  ou  pip install sqlmap"}), 400
    
    output = run_cmd(f"sqlmap -u \"{target}\" --batch --level=1 --risk=1 --banner 2>&1 | head -60", timeout=120)
    return jsonify({"target": target, "output": output})

# ─── Génération de rapport ────────────────────────────────────────────────────
@app.route("/api/report/generate", methods=["POST"])
@require_auth
def generate_report():
    data = request.json
    report_id = "RPT-" + str(uuid.uuid4())[:8].upper()
    
    report = {
        "id": report_id,
        "target": data.get("target", ""),
        "operator": session.get("user", "admin"),
        "date": datetime.datetime.now().isoformat(),
        "date_display": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
        "expiry": (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%d/%m/%Y"),
        "vulnerabilities": data.get("vulnerabilities", []),
        "dns_data": data.get("dns_data", {}),
        "scan_output": data.get("scan_output", ""),
        "modules_run": data.get("modules_run", []),
    }
    
    # Statistiques
    vulns = report["vulnerabilities"]
    report["stats"] = {
        "critical": sum(1 for v in vulns if v.get("severity") == "critical"),
        "high":     sum(1 for v in vulns if v.get("severity") == "high"),
        "medium":   sum(1 for v in vulns if v.get("severity") == "medium"),
        "low":      sum(1 for v in vulns if v.get("severity") == "low"),
        "total":    len(vulns),
    }
    
    # Sauvegarde JSON
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    return jsonify({"ok": True, "report_id": report_id, "report": report})

# ─── Liste des rapports ───────────────────────────────────────────────────────
@app.route("/api/reports")
@require_auth
def list_reports():
    reports = []
    for fname in os.listdir(REPORTS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(REPORTS_DIR, fname), encoding="utf-8") as f:
                    r = json.load(f)
                    reports.append({
                        "id": r["id"],
                        "target": r["target"],
                        "date_display": r["date_display"],
                        "expiry": r["expiry"],
                        "operator": r["operator"],
                        "stats": r.get("stats", {}),
                    })
            except: pass
    reports.sort(key=lambda x: x["id"], reverse=True)
    return jsonify(reports)

# ─── Téléchargement rapport HTML ─────────────────────────────────────────────
@app.route("/api/report/<report_id>/html")
@require_auth
def download_html(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        return "Rapport introuvable", 404
    with open(path, encoding="utf-8") as f:
        r = json.load(f)
    html = render_template("report_template.html", r=r)
    return html, 200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": f"attachment; filename=rapport_{report_id}.html"
    }

# ─── Téléchargement rapport JSON ─────────────────────────────────────────────
@app.route("/api/report/<report_id>/json")
@require_auth
def download_json(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        return "Rapport introuvable", 404
    return send_file(path, as_attachment=True, download_name=f"rapport_{report_id}.json")

# ─── Téléchargement rapport CSV ───────────────────────────────────────────────
@app.route("/api/report/<report_id>/csv")
@require_auth
def download_csv(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        return "Rapport introuvable", 404
    with open(path, encoding="utf-8") as f:
        r = json.load(f)
    
    lines = [
        f"# PenToolbox v4.0 — Rapport {r['id']} — {r['target']} — {r['date_display']}",
        "ID,Severite,Vulnerabilite,Module,Port,CVE,Recommandation"
    ]
    for i, v in enumerate(r.get("vulnerabilities", []), 1):
        lines.append(
            f"{i},{v.get('severity','')},\"{v.get('name','')}\","
            f"{v.get('module','')},{v.get('port','')},{v.get('cve','N/A')},"
            f"\"{v.get('recommendation','')}\""
        )
    
    return "\n".join(lines), 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": f"attachment; filename=rapport_{report_id}.csv"
    }

# ─── Suppression rapport ──────────────────────────────────────────────────────
@app.route("/api/report/<report_id>", methods=["DELETE"])
@require_auth
def delete_report(report_id):
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if os.path.exists(path):
        os.remove(path)
    return jsonify({"ok": True})

if __name__ == "__main__":
    import threading
    import webbrowser

    print("=" * 60)
    print("  PenToolbox v4.0 — Démarrage")
    print("=" * 60)
    print(f"  OS         : {platform.system()} {platform.release()}")
    print(f"  Python     : {platform.python_version()}")

    tools_check = ["nmap", "dig", "arp-scan", "nikto", "sqlmap"]
    for t in tools_check:
        status = "✓" if is_tool_available(t) else "✗ absent"
        print(f"  {t:<12}: {status}")

    print("=" * 60)
    print("  Interface  : http://localhost:5000")
    print("  Login      : admin / pentest2025")
    print("  Arrêt      : Ctrl+C")
    print("=" * 60)

    # Ouvre le navigateur automatiquement après 1.5s
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open("http://localhost:5000")
        print("  [+] Navigateur ouvert")

    threading.Thread(target=open_browser, daemon=True).start()

    import os
    # Docker utilise 0.0.0.0, Windows local utilise 127.0.0.1
    host = "0.0.0.0" if os.environ.get("DOCKER_ENV") else "127.0.0.1"
    print(f"  Serveur    : http://localhost:5000")
    app.run(host=host, port=5000, debug=False, use_reloader=False)
