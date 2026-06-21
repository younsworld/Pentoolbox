#!/bin/sh
# Entrypoint root -> bascule non-root (gosu). Raison d'etre : les dossiers
# runtime bind-montes (secrets/, config/, logs/, reports/) sont crees par le
# DAEMON Docker (root) s'ils n'existent pas encore sur l'hote — typiquement au
# tout premier `docker compose up` (le service nginx monte ../../secrets:ro pour
# lire les certs TLS, ce qui materialise le dossier en root:root avant meme que
# l'app pentoolbox ne demarre). Le process applicatif tournant en uid 1000
# (pentoolbox) ne peut alors plus y ecrire .secret_key/.fernet_key/cert.pem ->
# crash-loop "[Errno 13] Permission denied".
#
# On corrige ici, pendant qu'on est encore root (USER retire du Dockerfile au
# profit de cet entrypoint), puis on REtombe en non-root via gosu : l'app reste
# strictement non-root (setcap nmap/arp-scan + carve-out sudoers pentoolbox
# inchanges, cf. Dockerfile), seul ce court prologue est root. Idempotent :
# sans effet quand l'ownership est deja correct.
set -e

for d in secrets config logs reports; do
    mkdir -p "/app/$d"
    chown -R pentoolbox:pentoolbox "/app/$d"
done
chmod 700 /app/secrets

# exec : PID 1 devient le process applicatif (propagation correcte des signaux
# d'arret docker). "$@" = la CMD du Dockerfile (python app/app.py).
exec gosu pentoolbox "$@"
