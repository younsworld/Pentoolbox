FROM python:3.11-slim

LABEL maintainer="PenToolbox v4.0"

RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    arp-scan \
    net-tools \
    iputils-ping \
    curl \
    git \
    perl \
    gcc \
    libffi-dev \
    hydra \
    smbclient \
    samba-common-bin \
    libssl-dev \
    libnet-ssleay-perl \
    libcrypt-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    cpanminus \
    libcap2-bin \
    sudo \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Modules Perl manquants pour Nikto
RUN cpanm --notest JSON XML::Writer LWP::UserAgent HTTP::Request 2>/dev/null || true

# Nikto via git
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# enum4linux-ng (énumération SMB/NetBIOS/LDAP) — remplace l'ancien "Scan Réseau".
# Le paquet PyPI du même nom est un stub inutilisable -> on installe depuis le
# dépôt officiel + ses dépendances Python (les binaires samba smbclient/rpcclient/
# nmblookup viennent de smbclient/samba-common-bin dans la liste apt ci-dessus).
RUN git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng && \
    pip install --no-cache-dir ldap3 pyyaml impacket && \
    chmod +x /opt/enum4linux-ng/enum4linux-ng.py && \
    ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng

# ── SSH legacy (hydra/libssh) ─────────────────────────────────────────────────
# libssh 0.10+ (utilisé par hydra) désactive par défaut les algos obsolètes
# (ssh-rsa/ssh-dss en clé d'hôte, KEX group1-sha1, MACs hmac-sha1/md5…) que les
# vieilles cibles type Metasploitable 2 sont seules à proposer -> "kex error: no
# match for method server host key algo". Hydra n'expose AUCUN flag KEX ; le seul
# point de configuration est ce drop-in, lu par libssh via
# `Include /etc/ssh/ssh_config.d/*.conf` du ssh_config système (vérifié
# empiriquement). Les "+…" ajoutent aux défauts -> les cibles modernes restent OK.
RUN install -d /etc/ssh/ssh_config.d && \
    printf '%s\n' \
    '# PenToolbox: réactive les algos SSH legacy pour hydra (cibles obsolètes).' \
    'Host *' \
    '    HostKeyAlgorithms +ssh-rsa,ssh-dss' \
    '    KexAlgorithms +diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1' \
    '    PubkeyAcceptedAlgorithms +ssh-rsa' \
    '    Ciphers +aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc' \
    '    MACs +hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96,umac-64@openssh.com,hmac-ripemd160' \
    > /etc/ssh/ssh_config.d/99-pentoolbox-legacy.conf && \
    chmod 644 /etc/ssh/ssh_config.d/99-pentoolbox-legacy.conf

# ── Wordlists ─────────────────────────────────────────────────────────────────
# Détectées par /usr/share/wordlists/ côté backend (cf. HYDRA_WORDLIST_FILES).
# Téléchargements "best effort" (|| true) : si le build est hors-ligne, la
# wordlist absente est simplement masquée dans l'UI (available:false) au lieu de
# faire échouer le build. rockyou ≈ 133 Mo ; retirer la ligne pour une image lean.
RUN install -d /usr/share/wordlists && \
    (curl -fsSL -o /usr/share/wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt || echo "[build] rockyou non téléchargé (hors-ligne) — masqué dans l'UI") && \
    (curl -fsSL -o /usr/share/wordlists/ssh-betterdefaultpasslist.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt || true) && \
    printf '%s\n' root toor admin password 123456 msfadmin user test guest ubuntu pi raspberry vagrant kali postgres mysql oracle service backup nagios \
      changeme letmein qwerty abc123 password123 admin123 root123 welcome login pass 1234 12345 default support manager > /usr/share/wordlists/unix_passwords.txt

# ── John the Ripper (jumbo) — page "Cracking" ────────────────────────────────
# Le paquet Debian `john` est la version "core" : formats limités (descrypt,
# md5crypt, bcrypt…) SANS Raw-MD5/SHA1/SHA256/NTLM ni auto-détection utile. On
# compile donc John the Ripper "jumbo" depuis les sources Openwall, qui apporte
# ces formats + les règles (best64/jumbo). libssl-dev est déjà installé plus haut.
# Le wrapper /usr/local/bin/john EXEC le vrai binaire : john résout john.conf via
# argv[0] — un simple symlink le ferait chercher john.conf à côté du lien
# ("fopen: /usr/local/bin/john.conf: No such file"). Build "best effort" (|| …) :
# si le clone échoue (hors-ligne), l'UI affiche john "non installé" plutôt que de
# casser le build de toute l'image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential zlib1g-dev yasm libgmp-dev libpcap-dev pkg-config && \
    ( git clone --depth 1 https://github.com/openwall/john.git /opt/john-jumbo && \
      cd /opt/john-jumbo/src && ./configure && make -sj"$(nproc)" && \
      printf '#!/bin/sh\nexec /opt/john-jumbo/run/john "$@"\n' > /usr/local/bin/john && \
      chmod +x /usr/local/bin/john \
      || echo "[build] John jumbo non compilé — page Cracking indisponible (john absent)" ) && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir sqlmap

COPY app/ app/
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p reports
VOLUME ["/app/reports"]

# ── Utilisateur non-root ──────────────────────────────────────────────────────
# UID/GID 1000 choisis pour correspondre a l'utilisateur hote habituel
# (premier utilisateur non-root sur la plupart des distros Linux) afin que
# les fichiers crees via les bind-mounts (.:/app, reports/, secrets/,
# config/) gardent une ownership coherente cote hote plutot que root — avant
# cette restructuration, .secret_key/.fernet_key/.users/.settings.json/
# audit.log se retrouvaient root:root sur l'hote precisement parce que ce
# process tournait root dans le conteneur.
#
# IMPORTANT (verifie empiriquement, pas suppose): cap_add NET_ADMIN/NET_RAW
# au niveau du conteneur (docker-compose.yml) ne suffit PAS a lui seul a
# autoriser un process non-root a faire un scan nmap -sS/-sn ou arp-scan —
# les deux refusent tant que le BINAIRE lui-meme n'a pas de capabilities de
# fichier explicites. setcap les pose ici, sur l'image, pendant qu'on est
# encore root au build — elles survivent au changement d'utilisateur car
# attachees au fichier, pas au process.
#
# setcap suffit pour arp-scan (confirme: scan reel reussi en non-root) mais
# PAS pour nmap -sS/-O/-sU: ce build Debian d'nmap (ldd montre libcap.so.2,
# pas libcap-ng) ne verifie jamais les capabilities Linux a l'execution — il
# checke juste geteuid()==0 pour ces 3 types, donc setcap n'a aucun effet
# pour lui (confirme empiriquement, cf. carve-out sudo ci-dessous qui
# compense specifiquement ce cas).
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap && \
    setcap cap_net_raw,cap_net_admin+eip "$(command -v arp-scan)"

RUN groupadd -g 1000 pentoolbox && \
    useradd -u 1000 -g pentoolbox -M -s /usr/sbin/nologin pentoolbox && \
    chown -R pentoolbox:pentoolbox /app

# ── Sudo scope tres restreint, nmap uniquement ────────────────────────────────
# Carve-out pour les 3 templates de commande nmap construits par
# app.py::nmap_scan() (full/udp/stealth) qui ont besoin de root pour les raw
# sockets / OS fingerprinting (setcap ne marche pas pour nmap, voir plus
# haut). Pinned sur le prefixe de flags EXACT de chaque template — pas de
# wildcard sur les flags, seulement sur la cible en fin de ligne (variable
# par nature ; app.py::_is_safe_scan_target() valide sa forme avant de
# construire la commande sudo). Aucune autre commande, aucun shell general:
# `sudo -l` pour l'utilisateur pentoolbox ne liste que ces 3 lignes.
RUN echo "pentoolbox ALL=(root) NOPASSWD: /usr/bin/nmap -sV -sC -O -T4 -A --open *" > /etc/sudoers.d/pentoolbox-nmap && \
    echo "pentoolbox ALL=(root) NOPASSWD: /usr/bin/nmap -sU -T4 --top-ports 100 *" >> /etc/sudoers.d/pentoolbox-nmap && \
    echo "pentoolbox ALL=(root) NOPASSWD: /usr/bin/nmap -sS -T2 -f *" >> /etc/sudoers.d/pentoolbox-nmap && \
    chmod 0440 /etc/sudoers.d/pentoolbox-nmap && \
    visudo -cf /etc/sudoers.d/pentoolbox-nmap

# ── Entrypoint root -> non-root (gosu) ────────────────────────────────────────
# PAS de `USER pentoolbox` ici : le conteneur demarre root pour que
# entrypoint.sh puisse corriger l'ownership des bind-mounts runtime (secrets/
# notamment, cf. crash-loop "[Errno 13]" quand le daemon Docker cree le dossier
# en root au premier compose up), PUIS bascule en uid 1000 via `gosu pentoolbox`.
# L'application reste donc non-root — setcap nmap/arp-scan et le carve-out
# sudoers pentoolbox ci-dessus continuent de s'appliquer a l'identique (ils
# dependent de l'utilisateur d'execution et du binaire, pas du PID 1).
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5000
ENV DOCKER_ENV=1

# Utilise le DNS de la machine hote Windows pour resoudre les hostnames locaux
# Le DNS host est automatiquement detecte par Docker Desktop sur Windows
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "app/app.py"]
