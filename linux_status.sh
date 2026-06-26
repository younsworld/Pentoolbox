#!/bin/bash
# =============================================================================
#  PenToolbox — Etat des conteneurs Docker (Linux/Mac)
# =============================================================================
cd "$(dirname "$0")/deploy/docker" || exit 1
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}[X]${NC} Docker n'est pas installe. Lancez d'abord  ./linux_setup.sh"; exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}[X]${NC} Le service Docker n'est pas demarre  (sudo systemctl start docker)."; exit 1
fi

echo -e "${CYAN}=== Etat des conteneurs PenToolbox ===${NC}"
for c in pentoolbox pentoolbox-nginx openvas metasploit; do
    if docker inspect "$c" >/dev/null 2>&1; then
        state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)
        health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' "$c" 2>/dev/null)
        if [ "$state" = "running" ] && { [ "$health" = "healthy" ] || [ "$health" = "-" ]; }; then ic="${GREEN}●${NC}"
        elif [ "$health" = "starting" ]; then ic="${YELLOW}●${NC}"
        else ic="${RED}●${NC}"; fi
        printf "  %b %-18s %-10s %s\n" "$ic" "$c" "$state" "$health"
    else
        printf "  %b %-18s %s\n" "${RED}●${NC}" "$c" "absent (non cree)"
    fi
done
echo ""
echo -e "  Interface : ${CYAN}https://localhost/${NC}    Demarrer : ${CYAN}./linux_start.sh${NC}    Arret : ${CYAN}./linux_stop.sh${NC}"
