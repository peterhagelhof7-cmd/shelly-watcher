# shelly-watcher

Findet **alle Shelly-Geräte im Netzwerk** (Gen1, Plus/Pro (Gen2), Gen3, Gen4, Wall Display, auch Akkugeräte) und zeigt Modell, **Firmware-Version**, **veraltete Firmware**, IP, MAC, WLAN-Signal und Online-Status zentral auf einer Weboberfläche an. Alles läuft in einem kleinen Docker-Container, gedacht für ein NAS wie die Synology DS415+.

- **Sparsam:** ein statisches Go-Binary in einem `scratch`-Image, **ca. 15 MB RAM**, ca. 8 MB Image
- **Keine Cloud nötig:** spricht die Geräte direkt im LAN an (lokale HTTP-API)
- **Persistenz:** bekannte Geräte bleiben gespeichert, auch wenn sie gerade offline sind oder schlafen

## Schnellstart

```sh
docker compose up -d
```

Danach ist die Oberfläche unter `http://<NAS-IP>:8080` erreichbar. Der erste Scan läuft sofort und dauert für ein /24-Netz nur wenige Sekunden.

### Synology mit Paket „Docker“ (z.B. DS415+, DSM 7.0/7.1)

Die Oberfläche des Docker-Pakets kennt keine Compose-Projekte, deshalb wird der Container einmalig per SSH angelegt. Danach erscheint er ganz normal in der Docker-App und lässt sich dort starten, stoppen und das Log einsehen.

1. **Systemsteuerung → Terminal & SNMP → SSH-Dienst aktivieren.**
2. Per SSH als Administrator anmelden (`ssh admin@<NAS-IP>`), dann:

```sh
sudo mkdir -p /volume1/docker/shelly-watcher && cd /volume1/docker/shelly-watcher
sudo curl -LO https://raw.githubusercontent.com/peterhagelhof7-cmd/shelly-watcher/main/docker-compose.yml
sudo vi docker-compose.yml          # optional: SHELLY_PASSWORD, WEB_PASSWORD … eintragen
sudo docker-compose up -d
```

**Update auf eine neue Version:**

```sh
cd /volume1/docker/shelly-watcher && sudo docker-compose pull && sudo docker-compose up -d
```

Ohne Compose-Datei geht es auch mit einem einzigen Befehl:

```sh
sudo docker run -d --name shelly-watcher --network host --restart unless-stopped -m 64m   -e TZ=Europe/Berlin -v shelly-data:/data ghcr.io/peterhagelhof7-cmd/shelly-watcher:latest
```

Die Meldung `Your kernel does not support swap limit capabilities` ist auf Synology normal und harmlos.

### Synology mit Container Manager (DSM 7.2)

**Container Manager → Projekt → Erstellen**, als Quelle „docker-compose.yml erstellen“ wählen und den Inhalt von [`docker-compose.yml`](docker-compose.yml) einfügen.

> **Wichtig: `network_mode: host`.** Nur damit sieht der Container das echte LAN und empfängt mDNS-/CoIoT-Multicast. Im Bridge-Modus funktioniert nur der Subnetz-Scan, und `SCAN_CIDRS` muss gesetzt werden.

Falls Port 8080 auf dem NAS belegt ist: `LISTEN: ":8090"` setzen.

## Wie Geräte gefunden werden

| Weg | Findet | Hinweis |
|---|---|---|
| **Subnetz-Scan** (alle 15 min) | alle eingeschalteten Shellys | prüft Port 80 und fragt `/shelly` ab. Das ist die zuverlässigste Methode und funktioniert auch über VLAN-Grenzen per `SCAN_CIDRS` |
| **mDNS** (alle 5 min) | Gen1 (`_http._tcp`), Gen2+ (`_shelly._tcp`) | Anfrage von einem freien Port, kollidiert also nicht mit avahi auf der Synology |
| **CoIoT** (Port 5683/udp) | Gen1, auch **schlafende Akkugeräte** (H&T, Door/Window, Flood, Smoke, Button) | Gen1-Geräte senden ihren Status per Multicast. Beim Aufwachen werden sie sofort abgefragt |
| **Outbound WebSocket** `ws://<NAS-IP>:8080/ws` | Gen2+-**Akkugeräte** (Plus H&T, H&T Gen3, Plus Smoke, Flood Gen4 …) | im Gerät unter *Settings → Outbound WebSocket* eintragen. Das Gerät meldet sich bei jedem Aufwachen |
| **manuell** | einzelne IP | Eingabefeld in der Oberfläche |

Geräte werden über ihre **MAC-Adresse** geführt. Bekommt ein Shelly per DHCP eine neue IP, bleibt es derselbe Eintrag. Antwortet ein bekanntes Gerät nicht mehr unter seiner IP, startet sofort eine Neusuche, und es taucht nach wenigen Sekunden unter der neuen Adresse wieder auf.

Die Modellerkennung ist generisch: Jedes Gerät, das auf `/shelly` als Shelly antwortet, wird erfasst, auch Modelle, die es beim Schreiben dieses Programms noch nicht gab. Für lesbare Namen („Shelly Plus 1PM“ statt `SNSW-001P16EU`) gibt es eine Tabelle mit über 150 Modellen. Sie wird per `go generate` aus [aioshelly](https://github.com/home-assistant-libs/aioshelly) (Home Assistant, Apache-2.0) erzeugt. Unbekannte Codes werden mit dem `app`-Namen des Geräts angezeigt.

**Modell, MAC und Firmware-Version werden auch ohne Passwort gelesen.** `/shelly` ist bei allen Generationen frei zugänglich. Für Gerätename, WLAN-Signal, Laufzeit und die Update-Abfrage am Gerät wird bei passwortgeschützten Geräten `SHELLY_PASSWORD` benötigt (Gen1: Basic-Auth, Gen2+: Digest SHA-256).

## Veraltete Firmware

Ein Gerät gilt als **veraltet**, wenn seine Firmware älter ist als die neueste bekannte stabile Version für sein Modell. Die Referenz ist das Maximum aus drei Quellen:

1. **laut Gerät:** Das Shelly meldet selbst ein verfügbares Update (Gen1–Gen4). Dafür braucht das Gerät Internetzugang.
2. **laut Shelly-Firmwareliste:** Für Gen1 lädt der Container täglich die offizielle Liste von `api.shelly.cloud/files/firmware` (abschaltbar mit `FW_CHECK_ONLINE=false`). Das funktioniert auch für Shellys ohne Internet.
3. **Netzvergleich:** Ein anderes Gerät **desselben Modells** im Netz hat bereits eine neuere Version. Das funktioniert komplett offline, auch für Gen2+.

Beta-Versionen zählen nie als Referenz. In der Oberfläche gibt es dafür die Kachel bzw. den Filter „Firmware veraltet“, und die Modellübersicht zeigt pro Modell alle vorhandenen Firmware-Stände und markiert die veralteten.

## Konfiguration (Umgebungsvariablen)

| Variable | Standard | Bedeutung |
|---|---|---|
| `LISTEN` | `:8080` | Adresse/Port der Weboberfläche |
| `SCAN_CIDRS` | *(automatisch)* | Netze/IPs zum Scannen, z.B. `192.168.1.0/24, 10.0.20.0/24` (max. /16). Leer = alle LAN-Schnittstellen; Netze größer als /22 werden automatisch auf das eigene /24 begrenzt |
| `SCAN_INTERVAL` | `15m` | Abstand der Subnetz-Scans |
| `SCAN_CONCURRENCY` | `32` | parallele Verbindungsversuche beim Scan |
| `POLL_INTERVAL` | `1m` | Abfrage bekannter Geräte (Online-Status, Firmware) |
| `OFFLINE_AFTER` | `3×POLL_INTERVAL+30s` | ab wann ein Gerät als offline gilt |
| `SLEEPY_OFFLINE_AFTER` | `26h` | dasselbe für Akkugeräte (zeigen bis dahin „schläft“) |
| `SHELLY_USER` | `admin` | Benutzer für Gen1 (Gen2+ nutzt immer `admin`) |
| `SHELLY_PASSWORD` / `SHELLY_PASSWORD_FILE` | – | Passwort der Shellys (gleiches Passwort für alle) |
| `WEB_USER` / `WEB_PASSWORD` / `WEB_PASSWORD_FILE` | `admin` / – | schützt die Weboberfläche per Basic-Auth (`/ws` und `/healthz` bleiben frei) |
| `MDNS` / `MDNS_INTERVAL` | `true` / `5m` | mDNS-Suche |
| `COIOT` | `true` | CoIoT-Empfang auf 5683/udp |
| `FW_CHECK_ONLINE` | `true` | Gen1-Firmwareliste von Shelly laden |
| `HTTP_TIMEOUT` | `4s` | Zeitlimit pro Geräteabfrage |
| `SKIP_IFACES` | `docker,br-,veth,…` | Schnittstellen-Präfixe, die bei der Netzerkennung ignoriert werden |
| `DATA_DIR` | `/data` | Speicherort von `devices.json` |
| `DEBUG` | `false` | ausführliches Log |

## API

| Methode | Pfad | |
|---|---|---|
| GET | `/api/devices` | alle Geräte als JSON |
| GET | `/api/devices.csv` | CSV-Export (Excel-tauglich, `;`-getrennt) |
| POST | `/api/scan` | Scan sofort starten |
| POST | `/api/probe` (`ip=…`) | einzelne IP abfragen und hinzufügen |
| DELETE | `/api/devices/{mac}` | Gerät vergessen |
| GET | `/healthz` | Healthcheck |
| GET | `/ws` | Outbound-WebSocket-Endpunkt für Gen2+-Geräte |

## Grenzen

- **Shelly BLU** (Bluetooth) und **Shelly Wave** (Z-Wave) haben keine IP-Adresse und werden nicht erfasst.
- Für Gen2+ veröffentlicht Shelly keine Firmwareliste pro Modell. Dort stützt sich „veraltet“ auf die Meldung des Geräts und den Netzvergleich.
- Es wird ein gemeinsames Shelly-Passwort für alle Geräte unterstützt.
- Nur IPv4.

## Entwicklung

```sh
go test ./...
go run .                      # DATA_DIR=./data LISTEN=:8080 für lokal
go generate ./...             # Modelltabelle aus aioshelly aktualisieren
docker build -t shelly-watcher .
```

Entscheidungen und ihre Begründung stehen in [`docs/entscheidungen.md`](docs/entscheidungen.md).

## Lizenz

MIT. Die Modellnamen-Tabelle (`models_gen.go`) stammt aus [aioshelly](https://github.com/home-assistant-libs/aioshelly) (Apache-2.0). „Shelly“ ist eine Marke der Shelly Group. Dieses Projekt steht in keiner Verbindung zu ihr.
