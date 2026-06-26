#!/bin/bash
# =============================================================================
#  PenToolbox — Demarrer les conteneurs (Linux/Mac)
#  Pour la TOUTE PREMIERE installation, utilisez plutot ./linux_setup.sh
# =============================================================================
cd "$(dirname "$0")/deploy/docker" || exit 1
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}[X]${NC} Docker n'est pas installe. Lancez d'abord  ./linux_setup.sh"; exit 1
fi
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else echo -e "${RED}[X]${NC} docker compose introuvable. Lancez d'abord  ./linux_setup.sh"; exit 1; fi
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}[X]${NC} Le service Docker n'est pas demarre."
    echo -e "    Demarrez-le :  sudo systemctl start docker"; exit 1
fi

echo -e "${CYAN}[*]${NC} Demarrage de PenToolbox..."
if $DC up -d; then
    echo -e "${GREEN}[OK]${NC} Conteneurs demarres."
    echo ""
    $DC ps
    echo ""
    echo -e "  Interface : ${CYAN}https://localhost/${NC}"
    echo -e "  ${YELLOW}Note :${NC} OpenVAS peut mettre quelques minutes a devenir pret apres le demarrage."
    echo -e "  Etat : ${CYAN}./linux_status.sh${NC}    Arret : ${CYAN}./linux_stop.sh${NC}"
else
    echo -e "${RED}[X]${NC} Echec du demarrage. Voir les logs :  (cd deploy/docker && $DC logs)"; exit 1
fi
