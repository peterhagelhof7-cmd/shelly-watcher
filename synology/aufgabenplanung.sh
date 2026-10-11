# shelly-watcher für die Synology-Aufgabenplanung (Benutzer: root).
# Legt den Container an bzw. aktualisiert ihn. Gefundene Geräte bleiben erhalten.

# ===== VOR DEM AUSFÜHREN AUSFÜLLEN ==========================================
# Passwort deiner Shellys. Sind keine passwortgeschützt: ''
SHELLY_PASSWORD='HIER_EINTRAGEN'
# Passwort für die Weboberfläche (Benutzer: admin). Ohne Schutz: ''
WEB_PASSWORD='HIER_EINTRAGEN'
# Port der Weboberfläche
PORT=8080
# Passwörter in einfachen Anführungszeichen lassen, sie dürfen selbst kein ' enthalten.
# ===========================================================================

IMAGE=ghcr.io/peterhagelhof7-cmd/shelly-watcher:latest
DOCKER=/usr/local/bin/docker

case "$SHELLY_PASSWORD$WEB_PASSWORD" in
*HIER_EINTRAGEN*)
	echo "ABBRUCH: Bitte zuerst oben SHELLY_PASSWORD und WEB_PASSWORD ausfüllen (oder '' für keins)."
	exit 1
	;;
esac

$DOCKER pull "$IMAGE" || exit 1
$DOCKER rm -f shelly-watcher >/dev/null 2>&1
$DOCKER run -d --name shelly-watcher \
	--network host --restart unless-stopped -m 64m \
	-e TZ=Europe/Berlin \
	-e LISTEN=":$PORT" \
	-e SHELLY_PASSWORD="$SHELLY_PASSWORD" \
	-e WEB_PASSWORD="$WEB_PASSWORD" \
	-v shelly-data:/data \
	"$IMAGE" || exit 1
echo "OK: shelly-watcher läuft, Oberfläche unter http://<NAS-IP>:$PORT"
