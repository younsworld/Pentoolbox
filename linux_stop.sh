#!/bin/bash
# =============================================================================
#  PenToolbox — Arreter les conteneurs (Linux/Mac)
#  Les donnees (rapports, base OpenVAS, comptes) sont conservees.
# =============================================================================
cd "$(dirname "$0")/deploy/docker" || exit 1
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}[X]${NC} Docker n'est pas installe."; exit 1
fi
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else echo -e "${RED}[X]${NC} docker compose introuvable."; exit 1; fi

echo -e "${CYAN}[*]${NC} Arret de PenToolbox..."
if $DC down; then
    echo -e "${GREEN}[OK]${NC} Conteneurs arretes. (Les donnees/volumes sont conserves.)"
    echo -e "  Redemarrer :  ${CYAN}./linux_start.sh${NC}"
else
    echo -e "${RED}[X]${NC} Echec de l'arret."; exit 1
fi
