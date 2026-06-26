#!/bin/bash
# =============================================================================
#  PenToolbox — Installation/Lancement Docker en un clic (Linux/Mac)
#  Equivalent Linux de INSTALLER.bat : deploie la stack docker-compose complete
#  (PenToolbox + OpenVAS + Metasploit + Nginx), affiche la progression et
#  attend que les conteneurs cles soient "healthy".
#
#  Usage :  ./linux_setup.sh
# =============================================================================

# On se place dans le dossier du script (racine du projet) ; la stack compose
# vit dans deploy/docker/ et DOIT etre lancee depuis la (comme les .bat Windows :
# `cd deploy\docker` puis `docker compose up`) pour partager le meme nom de
# projet compose ("docker") et donc les memes volumes (openvas_data, etc.).
cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
COMPOSE_DIR="$ROOT/deploy/docker"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[~]${NC} $*"; }
err()  { echo -e "${RED}[X]${NC} $*"; }

echo -e "${CYAN}${BOLD}"
echo " ╔════════════════════════════════════════════════════╗"
echo " ║   PenToolbox — Deploiement Docker (Linux/Mac)      ║"
echo " ║   4 conteneurs : PenToolbox + OpenVAS + MSF + Nginx ║"
echo " ╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── 1. Pre-requis : Docker ────────────────────────────────────────────────
info "Verification de Docker..."
if ! command -v docker &>/dev/null; then
    err "Docker n'est pas installe."
    if command -v apt-get &>/dev/null; then
        echo "    Installer (Debian/Ubuntu/Kali) : sudo apt-get update && sudo apt-get install -y docker.io"
    elif command -v dnf &>/dev/null; then
        echo "    Installer (Fedora/RHEL)        : sudo dnf install -y docker"
    elif command -v pacman &>/dev/null; then
        echo "    Installer (Arch)               : sudo pacman -Sy --noconfirm docker"
    else
        echo "    Voir : https://docs.docker.com/engine/install/"
    fi
    echo "    Puis : sudo systemctl enable --now docker  (et ajouter votre user : sudo usermod -aG docker \$USER)"
    exit 1
fi
ok "Docker present ($(docker --version 2>/dev/null))"

# ─── 2. Pre-requis : docker compose (v2 plugin ou v1 binaire) ──────────────
info "Verification de docker compose..."
if docker compose version &>/dev/null; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    err "Le plugin 'docker compose' (v2) est absent."
    if command -v apt-get &>/dev/null; then
        echo "    Installer : sudo apt-get install -y docker-compose-plugin   (ou docker-compose)"
    else
        echo "    Voir : https://docs.docker.com/compose/install/"
    fi
    exit 1
fi
ok "Compose present ($DC)"

# ─── 3. Daemon Docker accessible ───────────────────────────────────────────
info "Verification de l'acces au daemon Docker..."
if ! docker info &>/dev/null; then
    err "Impossible de joindre le daemon Docker."
    echo "    - Demarrez-le : sudo systemctl start docker"
    echo "    - Droits      : ajoutez votre user au groupe docker (sudo usermod -aG docker \$USER) puis reconnectez-vous,"
    echo "                    ou relancez ce script avec sudo."
    exit 1
fi
ok "Daemon Docker accessible"

if [ ! -f "$COMPOSE_DIR/docker-compose.yml" ]; then
    err "docker-compose.yml introuvable dans $COMPOSE_DIR"
    exit 1
fi
cd "$COMPOSE_DIR" || exit 1

# ─── 4. Telechargement des images (progression visible) ────────────────────
echo ""
info "Telechargement des images Docker (OpenVAS ~1.5 Go, Metasploit, Nginx)..."
info "Cette etape peut etre longue au premier lancement — la progression s'affiche ci-dessous."
echo ""
if ! $DC pull; then
    warn "docker compose pull a renvoye une erreur (on tente quand meme up --build,"
    warn "l'image locale 'pentoolbox' sera construite et les autres re-essayees)."
fi

# ─── 5. Build + demarrage ──────────────────────────────────────────────────
echo ""
info "Construction de l'image PenToolbox et demarrage de la stack..."
if ! $DC up -d --build; then
    err "Echec de '$DC up -d --build'."
    echo "    Consultez les logs : (cd $COMPOSE_DIR && $DC logs)"
    exit 1
fi
ok "Conteneurs demarres. Verification de l'etat de sante..."

# ─── 6. Attente "healthy" ──────────────────────────────────────────────────
# pentoolbox + metasploit : rapides (< 1-2 min). openvas : long au 1er lancement
# (synchro du feed NVT/Notus, 30-90 min) -> best-effort, on ne bloque pas.
health() { docker inspect "$1" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null; }

wait_healthy() {  # $1=conteneur  $2=timeout_s  $3=label
    local c="$1" timeout="$2" label="$3" start=$SECONDS st
    printf "    %-26s " "$label"
    while [ $((SECONDS - start)) -lt "$timeout" ]; do
        st=$(health "$c")
        if [ "$st" = "healthy" ]; then echo -e "${GREEN}healthy${NC} ($((SECONDS-start))s)"; return 0; fi
        if [ "$st" = "none" ]; then
            # pas de healthcheck defini -> on verifie juste qu'il tourne
            if [ "$(docker inspect "$c" --format '{{.State.Running}}' 2>/dev/null)" = "true" ]; then
                echo -e "${GREEN}running${NC}"; return 0
            fi
        fi
        sleep 5
    done
    echo -e "${YELLOW}$(health "$c") (timeout ${timeout}s)${NC}"
    return 1
}

echo ""
info "Attente de la disponibilite des conteneurs :"
RC=0
wait_healthy pentoolbox      150 "PenToolbox (web)"      || RC=1
wait_healthy metasploit      150 "Metasploit (RPC)"      || RC=1
wait_healthy pentoolbox-nginx 60 "Nginx (proxy)"         || true

# OpenVAS : tres long au premier boot (feed NVT). On attend de maniere bornee,
# puis on informe sans considerer cela comme un echec.
echo ""
info "OpenVAS effectue au 1er lancement une synchro du feed NVT/Notus (30-90 min)."
info "Attente bornee (max 20 min) — sinon il continue en arriere-plan..."
if wait_healthy openvas 1200 "OpenVAS (scanner)"; then
    ok "OpenVAS est pret."
else
    warn "OpenVAS termine encore sa synchro du feed (normal au 1er lancement)."
    warn "Suivez l'avancement : (cd $COMPOSE_DIR && $DC logs -f openvas)"
    warn "Le reste de PenToolbox est deja utilisable ; les scans OpenVAS le seront"
    warn "une fois le feed synchronise."
fi

# ─── 7. Bilan ──────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}─────────────────────────────────────────────────────${NC}"
docker ps --filter "name=pentoolbox" --filter "name=openvas" --filter "name=metasploit" \
          --format "    {{.Names}}\t{{.Status}}" 2>/dev/null
echo -e "${CYAN}─────────────────────────────────────────────────────${NC}"
echo ""
if [ "$RC" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  PenToolbox est lance.${NC}"
else
    echo -e "${YELLOW}${BOLD}  PenToolbox est lance (certains services finissent de demarrer).${NC}"
fi
echo -e "  🌐 Interface  : ${CYAN}https://localhost/${NC}   (proxy Nginx, certificat auto-signe)"
echo -e "  🌐 OpenVAS GUI: ${CYAN}https://localhost:9392${NC}"
echo -e "  📋 Logs       : ${CYAN}(cd deploy/docker && $DC logs -f)${NC}"
echo -e "  ⏹  Arret      : ${CYAN}(cd deploy/docker && $DC down)${NC}"
echo ""
exit 0
