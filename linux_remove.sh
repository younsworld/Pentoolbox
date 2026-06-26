#!/bin/bash
# =============================================================================
#  PenToolbox — Supprimer / nettoyer l'installation Docker (Linux/Mac)
#  Equivalent Linux de DESINSTALLER.bat.
#
#  DESTRUCTIF : supprime les conteneurs, le reseau et les VOLUMES Docker
#  (base PostgreSQL + feed NVT d'OpenVAS, sessions Metasploit). Le feed OpenVAS
#  devra etre resynchronise au prochain ./linux_setup.sh.
#
#  CONSERVE : les dossiers de l'HOTE  reports/  et  secrets/  (montages bind,
#  donc PAS dans les volumes Docker) -> vos rapports et vos comptes survivent.
#
#  Usage :  ./linux_remove.sh         (interactif, demande confirmation)
#           ./linux_remove.sh -y      (sans confirmation ; conserve les images telechargees)
# =============================================================================
cd "$(dirname "$0")/deploy/docker" || exit 1
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

ASSUME_YES=0
case "$1" in -y|--yes) ASSUME_YES=1 ;; esac

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}[X]${NC} Docker n'est pas installe — rien a nettoyer."; exit 1
fi
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else echo -e "${RED}[X]${NC} docker compose introuvable."; exit 1; fi

echo -e "${RED}${BOLD}"
echo " ╔════════════════════════════════════════════════════╗"
echo " ║   PenToolbox — SUPPRESSION de l'installation Docker ║"
echo " ╚════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}Vont etre SUPPRIMES :${NC}"
echo "   - les 4 conteneurs (pentoolbox, openvas, metasploit, nginx) + le reseau"
echo "   - les VOLUMES Docker : base + feed NVT OpenVAS, donnees Metasploit"
echo "   - l'image PenToolbox construite localement"
echo -e "${GREEN}Seront CONSERVES :${NC} vos dossiers  reports/  et  secrets/  (sur l'hote)."
echo ""

# ─── Confirmation (sauf -y) ────────────────────────────────────────────────
REMOVE_IMAGES=0
if [ "$ASSUME_YES" -eq 0 ]; then
    printf "Confirmer la suppression ? Tapez %boui%b : " "$BOLD" "$NC"
    read -r ANS
    case "$ANS" in
        oui|OUI|yes|YES) ;;
        *) echo -e "${CYAN}[i]${NC} Annule — rien n'a ete supprime."; exit 0 ;;
    esac
    printf "Supprimer aussi les images TELECHARGEES (OpenVAS ~1.5 Go, Metasploit, Nginx) ? [o/N] : "
    read -r IMG
    case "$IMG" in o|O|oui|OUI|y|Y|yes|YES) REMOVE_IMAGES=1 ;; esac
fi

# --rmi local : ne supprime que l'image construite (PenToolbox). --rmi all :
# supprime aussi les images telechargees (re-telechargement au prochain setup).
RMI="local"; [ "$REMOVE_IMAGES" -eq 1 ] && RMI="all"

echo ""
echo -e "${CYAN}[*]${NC} Suppression des conteneurs, du reseau et des volumes (--rmi $RMI)..."
$DC down -v --rmi "$RMI" --remove-orphans

# Filets de securite : restes eventuels de l'installeur mono-conteneur (.bat)
docker rm -f pentoolbox >/dev/null 2>&1
docker rmi pentoolbox:latest >/dev/null 2>&1

echo ""
echo -e "${GREEN}[OK]${NC} Nettoyage termine."
echo -e "   Reinstaller : ${CYAN}./linux_setup.sh${NC}"
echo -e "   (reports/ et secrets/ ont ete conserves sur l'hote.)"
