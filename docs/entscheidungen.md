# Entscheidungen

Laufendes Log nicht offensichtlicher Entscheidungen, neueste unten.

## 2026-10-11 – Projektstart

**Sprache Go, Image `FROM scratch`.** Vorgabe war sparsamer RAM auf einer DS415+ (2 GB). Ein statisches Go-Binary braucht gemessen ca. 15 MB RSS (Linux/WSL, nach Start und nach /24-Scan), das Image ist ca. 8 MB groß. Python/Node hätten mit Laufzeitumgebung ein Mehrfaches gebraucht. `GOMEMLIMIT=24MiB` im Image, `mem_limit: 64m` in der Compose-Datei. Einzige Abhängigkeit ist `golang.org/x/net` (DNS-Nachrichten, Multicast, WebSocket).

**Erkennung über `/shelly`.** Der Endpunkt existiert bei allen Generationen und ist auch bei aktivem Passwortschutz frei zugänglich. Er liefert Modellcode, MAC und Firmware. Damit werden „alle Modelle mit Firmware“ erfasst, auch zukünftige und auch ohne Passwort. Gen1 und Gen2+ werden an den Feldern unterschieden (`type` bzw. `gen`).

**Vier Discovery-Wege statt einem.** Der Subnetz-Scan ist die Basis, weil mDNS bei Shellys unzuverlässig ist (Gen1 bewirbt sich teils gar nicht). Allein reicht der Scan aber nicht, weil Akkugeräte schlafen. Deshalb gibt es zusätzlich CoIoT (Gen1-Akkugeräte senden beim Aufwachen) und den Outbound WebSocket (Gen2+-Akkugeräte verbinden sich beim Aufwachen selbst).

**mDNS als „legacy unicast“ von einem zufälligen Port.** Auf der Synology belegt avahi Port 5353. Statt diesen Port mitzubenutzen, wird von einem freien Port gefragt (RFC 6762 6.7). Die Geräte antworten dann direkt dorthin.

**CoIoT-Hinweise nur mit voller MAC anlegen.** Option 3332 enthält je nach Firmware die volle MAC oder nur die letzten 6 Stellen. Mit 6 Stellen wird nur ein bekanntes Gerät aktualisiert, sonst gäbe es Phantom-Einträge.

**Host-Netzwerk ist Pflicht für Multicast.** Im Bridge-Modus kommen mDNS/CoIoT nicht an und die LAN-Erkennung sieht nur das Docker-Netz. Docker-/VM-Schnittstellen (`docker*`, `br-*`, `veth*` …) werden bei der automatischen Netzerkennung ignoriert. Auf der Synology bleibt `ovs_eth0` (Open vSwitch bei aktivem VMM) bewusst drin, weil das das echte LAN ist.

**Automatischer Scan höchstens /22, sonst nur das eigene /24.** Damit ein /16-Firmennetz nicht versehentlich 65 000 Adressen scannt. Explizit über `SCAN_CIDRS` sind bis /16 erlaubt.

**Nicht-root im Container, benanntes Volume als Standard.** Das Image läuft als UID 65534. Ein benanntes Volume übernimmt die Rechte des vorbereiteten `/data` und funktioniert ohne weitere Einrichtung. Ein Bind-Mount auf `/volume1/...` gehört dem DSM-Benutzer und wäre ohne `user:` bzw. `chmod` nicht beschreibbar. Wenn `DATA_DIR` nicht beschreibbar ist, läuft das Programm ohne Persistenz weiter, statt abzubrechen.

**Outbound WebSocket: Request-IDs pro Auth-Runde.** Gefunden durch den Test mit einem simulierten Plus H&T: Beide ersten Anfragen (GetDeviceInfo, GetStatus) bekommen ohne Auth ein 401. Das zweite 401 kam erst an, nachdem die Auth-Runde schon gestartet war, und wurde als „Passwort falsch“ gewertet. Echte Geräte verhalten sich genauso. Jede Runde hat jetzt eigene IDs (`runde*10 + n`), und Antworten aus alten Runden werden ignoriert.

**Ohne Passwort kommt die MAC per WebSocket aus der Absender-ID.** Bei passwortgeschütztem Gerät und fehlendem `SHELLY_PASSWORD` antwortet auch GetDeviceInfo mit 401. Die Absender-ID (`shellyplusht-08b61fcd1234`) enthält aber die MAC, das Gerät wird also trotzdem gelistet.

**Modelltabelle aus aioshelly generiert, nicht von Hand.** Home Assistant pflegt die Liste der Modellcodes aktiv. `go generate` zieht sie neu (154 Modelle am 2026-10-11). Zwei ursprünglich von mir ergänzte Codes (`SHSW-22`, `SHHT-2`) waren nicht belegt und wurden wieder entfernt. Unbekannte Codes werden mit dem `app`-Feld des Geräts benannt (z.B. „Shelly Plus 1PM“ aus `Plus1PM`).

**Farbschema von home-central übernommen** (Wunsch des Nutzers): dunkelblau, Kartenlayout, gleiche CSS-Variablen. Wie dort gibt es bewusst nur ein dunkles Schema.

## 2026-10-11 – Veraltete Firmware

**„Veraltet“ = älter als die neueste bekannte stabile Version für das Modell**, die Referenz ist das Maximum aus drei Quellen: Meldung des Geräts, offizielle Gen1-Liste und Netzvergleich (ein Gerät gleichen Modells hat eine neuere Version).

**Gen1-Liste `api.shelly.cloud/files/firmware`:** am 2026-10-11 live geprüft, liefert 42 Gen1-Modelle mit stabiler und Beta-Version. Für Gen2+ habe ich **keinen** dokumentierten Endpunkt gefunden. Versuche mit `updates.shelly.cloud/update/<app>` liefen ins Leere, die Doku nennt nur die gerätelokale Abfrage (`Shelly.CheckForUpdate` / `sys.available_updates`). Ich habe deshalb bewusst keine URL geraten. Für Gen2+ gelten nur Gerätemeldung und Netzvergleich.

**Beta zählt nie als Referenz**, sonst wäre jedes Gerät auf Stable „veraltet“, sobald ein anderes eine Beta fährt. Eine Vorabversion gilt beim Vergleich als älter als die zugehörige Release-Version (`1.5.0-beta1 < 1.5.0`).

## 2026-10-11 – IP-Wechsel (DHCP)

**Geräte werden über die MAC geführt.** Eine neue IP aktualisiert den vorhandenen Eintrag, Name, „Zuerst gesehen“ und Quellen bleiben. Eine IP gehört immer nur einem Eintrag. Wer sie neu meldet, bekommt sie, beim bisherigen Inhaber wird sie gelöscht (`Store.setIP`). Vorher galt das nur für vollständige Abfragen. Ein CoIoT-Hinweis konnte kurzzeitig zwei Einträge mit derselben IP erzeugen (Bug, jetzt behoben).

**Sofortige Neusuche bei Verlust.** Schlägt der regelmäßige Poll eines bisher fehlerfreien Geräts fehl oder antwortet unter seiner IP plötzlich ein anderes Gerät, startet sofort eine mDNS-Suche und ein Scan. Vorher dauerte das bis zum nächsten regulären Scan, also bis zu 15 min.
- Ausgelöst wird nur beim **Übergang** ok → Fehler. Ein ausgeschaltetes Gerät würde sonst minütlich einen Scan auslösen.
- Ausgelöst wird nur beim **Poll** und nicht bei Abfragen nach CoIoT/WebSocket, denn ein wieder eingeschlafenes Akkugerät ist kein Verlust.
- Höchstens eine Neusuche alle 2 min, auch wenn mehrere Geräte gleichzeitig verschwinden (z.B. beim Neustart des Routers).

## 2026-10-11 – Synology ohne Container Manager

**Die DS415+ hat nur das alte Paket „Docker“** (Hinweis des Nutzers), ohne Compose-Projekte in der Oberfläche. Die Anleitung legt den Container deshalb einmalig per SSH mit `docker-compose` an, einem Docker run-Befehl als Alternative. Die Compose-Datei ist mit `docker-compose` 1.28.5 (der Version im Synology-Paket) per `config` geprüft und läuft unverändert.

**Image ohne Attestations** (`provenance: false`, `sbom: false`): buildx hängt sonst Einträge mit Plattform „unknown/unknown“ an den Image-Index. Ältere Docker-Versionen (Synology-Paket: 20.10) kommen damit schlecht zurecht. Der Index enthält jetzt nur noch die drei echten Plattformen.

**Hauptweg ist die Aufgabenplanung statt SSH** (Wunsch des Nutzers: nur Weboberfläche). Das Script in `synology/aufgabenplanung.sh` legt den Container per `docker run` an bzw. neu an und dient gleichzeitig als Updater. Die auszufüllenden Werte stehen **oben** und haben den Platzhalter `HIER_EINTRAGEN`. Solange einer davon da ist, bricht das Script ab. Anlass: Die erste Fassung hatte leere Werte, und der Hinweis stand erst unter dem Script. Der Nutzer hat es so ausgeführt und lief ohne Passwörter. Passwörter stehen in einfachen Anführungszeichen. In WSL mit einem Docker-Stub getestet: Abbruch bei Platzhalter, Sonderzeichen (`$ " & ! `` ` `` Leerzeichen`) kommen unverändert an, leere Werte gehen.

## 2026-10-11 – WLAN-Farben, Detailseite, Shelly-Konto

**WLAN-Schwellen:** gut ab −67 dBm, ausreichend bis −79 dBm, darunter schlecht. −67 dBm ist die übliche Grenze für stabiles WLAN, unter −80 dBm sind Abbrüche wahrscheinlich. Gen2+ mit aktiver LAN-IP und ohne WLAN-RSSI gelten als „LAN“.

**Messwerte ohne Zusatzabfragen:** Der Poll liest ohnehin den vollständigen Status (`Shelly.GetStatus` bzw. `/status`). Daraus werden die Kanäle gebildet und gespeichert. Nur die Detailseite liest zusätzlich die Konfiguration (Kanalnamen, Cloud-Server). Namen und Server bleiben bei späteren Polls erhalten (`mergeDetail`). `/api/devices` schickt keine Messwerte mit, damit die Übersicht schlank bleibt.

**Generische Kanäle statt Modelltabellen:** Gen2+ liefert Komponenten als `typ:id`. Alle außer Systemkomponenten (sys, wifi, cloud …) werden angezeigt. Bekannte Felder bekommen deutsche Namen, Einheiten und Umrechnung (Wh → kWh), unbekannte werden roh angezeigt. Damit sind auch künftige Modelle ohne Codeänderung abgedeckt. Gen1 wird aus relays/meters/emeters/lights/rollers/inputs und den Sensorfeldern gebildet. Achtung: `meters[].total` ist bei Gen1 in **Wattminuten**, `emeters[].total` dagegen in Wh.

**Shelly-Konto ist lokal nicht lesbar.** Weder Gen1 (`/settings`, `/status`) noch Gen2+ (`Shelly.GetConfig`, `Cloud.GetConfig`) liefern das verknüpfte Konto. Angezeigt werden Cloud aktiviert/verbunden und bei Gen2+ der Cloud-Server. Eine Zuordnung zum Konto wäre nur über die Shelly-Cloud-API mit dem Auth-Key je Konto möglich (legacy `device/all_status`, laut Shelly abgekündigt). Das ist offen und wird mit dem Nutzer entschieden.

## 2026-10-11 – Einstellungsseite, Info-Seite, Version 1.0.0

**Shelly-Konto bleibt bei der lokalen Anzeige** (Nutzer hat nur ein Konto). Keine Anbindung an die Cloud-API.

**Was einstellbar ist:** Werte, die man im Betrieb wirklich anpasst: Netze, Scan-/Abfrage-Intervall, mDNS, CoIoT, Offline-Grenze für Akkugeräte, Shelly-Benutzer/-Passwort, Gen1-Firmwareliste, WLAN-Farbgrenzen, Benutzer/Passwort der Oberfläche, ausführliches Log. **Bewusst nicht** in der Oberfläche: Port (`LISTEN`), `DATA_DIR`, Timeouts, Schnittstellenfilter. Eine falsche Einstellung dort kann die Oberfläche selbst unerreichbar machen, ohne dass man sie über die Oberfläche wieder reparieren kann.

**Umgebung = Startwert, Oberfläche hat Vorrang.** Die Konfiguration ist ein unveränderlicher Schnappschuss (`atomic.Pointer`). Speichern erzeugt einen neuen, und alle Teile lesen bei jeder Verwendung den aktuellen. Schleifen (Scan, Poll, mDNS, Firmwareliste, CoIoT) werden über einen Änderungskanal geweckt. So greift alles ohne Neustart, und es gibt keine Datenrennen (`go test -race`).

**Passwörter:** werden nie an den Browser ausgeliefert, nur ihre Herkunft (nicht gesetzt / Umgebung / Oberfläche). Das Web-Passwort wird als PBKDF2-SHA256 gespeichert (100 000 Iterationen, Go-Standardbibliothek, keine neue Abhängigkeit). Das Shelly-Passwort muss im Klartext liegen, weil es für Basic- bzw. Digest-Auth gebraucht wird. Die Datei hat deshalb Rechte 0600.

**Notausgang `SETTINGS_RESET=true`:** Wer sich mit einem in der Oberfläche gesetzten Web-Passwort aussperrt, kommt ohne SSH nicht an `/data/settings.json` (Docker-Volume). Die Variable lässt sich im Aufgabenplanungs-Script setzen und verwirft die Datei beim Start.

**Kein `confirm()`-Dialog** beim Entfernen eines Passworts. Stattdessen bestätigt ein zweiter Klick. Das ist robuster und blockiert die Seite nicht.

**Image-Tags: `latest` nur für Releases.** Bis 1.0.0 setzte jeder Push auf `main` `latest`. Das Synology-Script aktualisiert aber wöchentlich `:latest` und hätte damit jeden Zwischenstand installiert. Jetzt gilt: `latest` und `X.Y.Z`/`X.Y` nur bei einem Tag `vX.Y.Z`, `main` erzeugt `edge`.
