#######################################################################
# NTRIP All-in-One Image — Caster + GGA-Proxy + Backend in einem Container
# (per Supervisor verwaltet). Fuer Portabilitaet/Weitergabe; produktiv
# empfehlen wir weiterhin die getrennten Container (siehe Haupt-Compose).
#######################################################################

# ---- Stage 1: Caster bauen (wie im separaten Caster-Dockerfile) ----
FROM debian:bookworm-slim AS caster-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libreadline-dev ca-certificates wget \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY build/ntripcaster-2.0.49 /build/ntripcaster-2.0.49
WORKDIR /build/ntripcaster-2.0.49
RUN ./configure --disable-systemd \
 && make -j"$(nproc)" \
 && make install

# ---- Stage 2: Finales Image mit Python + Supervisor + Caster-Binaries ----
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libreadline8 ca-certificates supervisor iproute2 \
 && rm -rf /var/lib/apt/lists/*

# Caster
COPY --from=caster-builder /usr/local/ntripcaster /usr/local/ntripcaster

# Backend (app.py erwartet /app/static absolut, daher Inhalt direkt nach /app)
COPY backend/app.py /app/app.py
COPY backend/static /app/static
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# GGA-Proxy
COPY gga-proxy /app/gga-proxy
RUN pip install --no-cache-dir -r /app/gga-proxy/requirements.txt

# Caster-Konfiguration (Startzustand; wird i.d.R. per Volume ueberschrieben)
COPY conf /usr/local/ntripcaster/conf
# Backend erwartet die Config fest unter /conf (siehe app.py CONF_DIR) --
# Symlink auf den gemeinsamen Caster-Conf-Ordner, damit beide dieselben
# Dateien sehen (Single Source of Truth, kein doppeltes Volume noetig).
RUN ln -s /usr/local/ntripcaster/conf /conf

# Supervisor-Konfiguration
COPY supervisord.conf /etc/supervisor/conf.d/ntrip.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/usr/local/ntripcaster/conf", "/usr/local/ntripcaster/logs", "/data"]

# 5000 = NTRIP (oeffentlich, via gga-proxy), 80 = Caster-Admin-Webinterface,
# 8000 = Backend-Weboberflaeche (Nutzerverwaltung, Karte, Alarme, Failover)
EXPOSE 5000 80 8000

ENTRYPOINT ["/entrypoint.sh"]
