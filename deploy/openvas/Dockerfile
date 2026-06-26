FROM immauss/openvas:latest

# Fix: l'image :latest embarque ospd-openvas 22.10.1 avec redis-py >=5.3, qui
# active par defaut la gestion des "maintenance notifications" et suppose un
# attribut .host sur la connexion Redis. ospd-openvas parle a Redis via socket
# Unix (pas de .host) -> crash au demarrage avec:
#   ValueError: Cannot enable maintenance notifications for connection object
#   that doesn't have a host attribute.
# redis<5.3 ne porte pas cette logique -> ospd-openvas demarre normalement.
# A retirer si une future version d'immauss/openvas corrige le pin en amont.
RUN pip3 install --break-system-packages --no-cache-dir "redis<5.3"
