# NTRIP All-in-One

Eigener NTRIP-Caster fuer RTK-Korrekturdaten in einem Docker-Container, mit Web-GUI:

- **NtripCaster 2.0.49** (BKG, GPL) als Kern, baut aus `build/` (Relay-Pull der eigenen Basisstation
  und fremder Caster wie EUREF-IP, IGN, RTK2go)
- **GGA-Proxy** (`gga-proxy/proxy.py`, oeffentlicher Port 5000): liest Rover-Positionen mit, leitet NTRIP
  unveraendert durch (v1/v2), virtueller Mountpoint `/NEAR` (automatische Stationswahl), Failover auf
  Backup-Stationen, Schutz des oeffentlichen Ports
- **Backend + GUI** (`backend/`, FastAPI, Port 8000): Benutzer, Stationen, Karten mit Abdeckung,
  Verlauf, Mehrfachnutzungs-Alarm, Failover, Systemeinstellungen und Passwoerter

## Aufbau

| Pfad | Inhalt |
|---|---|
| `Dockerfile`, `supervisord.conf`, `entrypoint.sh` | Image-Bauplan (alle drei Dienste per Supervisor) |
| `backend/` | `app.py` (API), `static/index.html` (GUI) |
| `gga-proxy/` | `proxy.py` |
| `build/ntripcaster-2.0.49/` | Quellcode des BKG NtripCaster (GPL) |
| `conf/` | Startkonfiguration des Casters (nur Beispielwerte) |
| `tools/rtk_check.py` | Prueft einen RTCM-Strom auf RTK-Tauglichkeit |
| `rebuild.sh` | Image neu bauen und Container neu anlegen |

## Schnellstart

```bash
docker build -t ntrip-allinone .

mkdir -p data/db data/logs data/conf
cp conf/* data/conf/

docker run -d --name ntrip-allinone --restart unless-stopped \
  --add-host ntripcaster:127.0.0.1 \
  -e ADMIN_TOKEN='<login-token-der-gui>' \
  -e CASTER_ADMIN_PASS='<caster-admin-passwort>' \
  -e PUBLIC_HOSTNAME='ntrip.example.org' -e PUBLIC_NTRIP_PORT=5000 \
  -e TRIMBLE_HOST='192.168.0.10' -e TRIMBLE_PORTS=28001,28002 \
  -e BASE_LAT=52.52 -e BASE_LON=13.40 \
  -v "$PWD/data/db:/data" -v "$PWD/data/conf:/usr/local/ntripcaster/conf" \
  -v "$PWD/data/logs:/usr/local/ntripcaster/logs" \
  -p 5000:5000 -p 8001:8000 -p 8090:80 \
  ntrip-allinone
```

| Port | Zweck |
|---|---|
| 5000 | NTRIP (Proxy, oeffentlich freigeben) |
| 8001 | Web-GUI (Login mit `ADMIN_TOKEN`; nicht ins Internet stellen) |
| 8090 | Weboberflaeche des Casters |

`ADMIN_TOKEN` und `CASTER_ADMIN_PASS` werden nur beim ersten Start in die Datenbank uebernommen;
danach aendert man sie in der GUI (Einstellungen). Dort stehen auch alle weiteren Einstellungen
(Basisstation, /NEAR, Failover, Abdeckungsradius, Aufbewahrung).

## Hinweise

- Rover-Passwoerter liegen im Klartext in der DB und in `users.aut` (der Caster kann nur Klartext/crypt()).
  Fuer jeden Rover ein eigenes Passwort verwenden.
- Der Admin-Bereich des Casters (`/admin`, `/oper`) wird vom Proxy nach aussen nie durchgereicht.
- `data/` (Datenbank, Konfiguration, Logs) gehoert nicht ins Repository.
- Der Caster unter `build/` steht unter der GPL (BKG NtripCaster); Hinweise dort in `COPYING`.

## Lizenz

Eigener Code: **GPL-3.0-or-later** (siehe [`LICENSE`](LICENSE)). Enthaltener BKG NtripCaster: GPL, Copyright
BKG; Details, Drittkomponenten und Kartenquellen in [`NOTICE.md`](NOTICE.md).
