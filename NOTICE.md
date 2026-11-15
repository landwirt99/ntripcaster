# Lizenzhinweise

## Eigener Code

Copyright (C) 2026 landwirt99

Backend (`backend/`), GGA-Proxy (`gga-proxy/`), `tools/`, `rebuild.sh`, `entrypoint.sh`, Dockerfile und
Konfigurationsvorlagen stehen unter der **GNU General Public License, Version 3 oder (nach Wahl) jeder
spaeteren Version** (SPDX: `GPL-3.0-or-later`). Der Volltext steht in [`LICENSE`](LICENSE).

## BKG NtripCaster (enthalten in `build/ntripcaster-2.0.49/`)

Der Kern dieses Projekts ist der **BKG Professional NtripCaster 2.0.49**.

- Copyright (c) 2003-2024 Bundesamt fuer Kartographie und Geodaesie (BKG), Frankfurt am Main
  (German Federal Agency for Cartography and Geodesy); entwickelt fuer NTRIP, Entwurf: Informatik
  Centrum Dortmund (ICD).
- Basiert auf dem unter der GPL veroeffentlichten **Icecast 1.3.12**.
- Lizenz: GNU General Public License. Die Quelldateien nennen "Version 3 oder spaeter" (die meisten) bzw.
  "Version 2 oder spaeter" (einige aeltere). Der Quellcode-Baum enthaelt den GPLv2-Text
  (`build/ntripcaster-2.0.49/COPYING`); die GPLv3 liegt im Hauptverzeichnis als `LICENSE`.
- Bezugsquelle: https://igs.bkg.bund.de/root_ftp/NTRIP/software/caster/ntripcaster-2.0.49.tar.bz2
  (SHA-256 `731e7403c7eeb9348e6d18474e02981d08ec702ade2bf56bc93fa81954dcfa9b`, entspricht der vom BKG
  veroeffentlichten Pruefsumme). Das BKG gibt den Caster seit September 2024 kostenlos samt Quellcode ab.
- Der Quellcode wird hier unveraendert mitgeliefert (Datei-fuer-Datei-Vergleich mit dem Original-Tarball: identisch), damit Image und Quelltext zusammen weitergegeben
  werden koennen (GPL: Quellcode muss verfuegbar sein). Urheberrechtsvermerke und Lizenzkopfzeilen
  der Quelldateien duerfen nicht entfernt werden.
- Haftungsausschluss des BKG (aus den Quelldateien): Das BKG uebernimmt keine Haftung fuer Schaeden,
  die direkt oder indirekt durch die Nutzung der NTRIP-Technologie entstehen.

Der Caster laeuft als eigener Prozess; GGA-Proxy und Backend sprechen nur ueber das Netzwerk (HTTP/NTRIP)
mit ihm. Beide Teile werden gemeinsam in einem Docker-Image ausgeliefert ("blosse Zusammenstellung");
fuer den Caster-Teil gelten die GPL-Bedingungen oben.

## Weitere Komponenten (nicht im Repository enthalten, werden beim Bau/Betrieb geladen)

| Komponente | Lizenz |
|---|---|
| FastAPI | MIT |
| Uvicorn | BSD-3-Clause |
| Requests | Apache-2.0 |
| HTTPX | BSD-3-Clause |
| Pydantic | MIT |
| Supervisor | BSD-aehnlich (Repoze/ZPL-Variante) |
| Leaflet 1.9.4 (GUI, per CDN von unpkg.com) | BSD-2-Clause |
| Python (Docker-Basisimage), Debian | PSF bzw. diverse (Debian) |

## Kartendaten in der GUI (werden zur Laufzeit von Drittanbietern geladen)

Die GUI zeigt Kacheln von **Esri World Imagery / Reference** (Nutzungsbedingungen von Esri,
Quellenangabe wird in der Karte angezeigt), **OpenStreetMap** (c) OpenStreetMap-Mitwirkende, ODbL, und
**OpenTopoMap** (CC-BY-SA, Daten OSM/SRTM). Bitte deren jeweilige Nutzungsbedingungen beachten,
insbesondere bei oeffentlichem oder hohem Kartenverkehr.

Die Sourcetable-Daten fremder Caster (EUREF-IP, IGN, RTK2go u. a.) unterliegen den Nutzungsbedingungen
der jeweiligen Betreiber; fuer den Datenstrom ist dort ein eigener Zugang erforderlich.
