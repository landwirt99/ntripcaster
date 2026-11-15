#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 landwirt99
# Baut das Image aus diesem Ordner und legt den Container "ntrip-allinone" neu an.
# Alle Daten (DB, Caster-Konfiguration, Logs) liegen in ./data und bleiben erhalten.
# Umgebungsvariablen, Ports und Mounts werden vom laufenden Container uebernommen.
# Aufruf:  ./rebuild.sh [tag]      (Standard-Tag: Datum/Uhrzeit)
# Rollback: docker stop ntrip-allinone && docker rm ntrip-allinone-old   ... bzw. altes Image-Tag starten.
set -e
cd "$(dirname "$0")"
TAG="${1:-$(date +%Y%m%d-%H%M)}"
docker build -t "ntrip-allinone:$TAG" -t ntrip-allinone:latest .
python3 - "$TAG" <<'PY'
import json, subprocess, sys
tag = sys.argv[1]
def sh(*a, check=False):
    r = subprocess.run(a, capture_output=True, text=True)
    print(" ".join(a[:4]), "->", r.returncode, (r.stdout + r.stderr).strip()[:200])
    if check and r.returncode: sys.exit(1)
    return r
info = json.loads(subprocess.check_output(["docker", "inspect", "ntrip-allinone"]))[0]
keys = ("TRIMBLE_PORTS", "BASE_LAT", "BASE_LON", "CASTER_ADMIN_PASS", "ADMIN_TOKEN",
        "PUBLIC_HOSTNAME", "PUBLIC_NTRIP_PORT", "TRIMBLE_HOST")
env = [e for e in info["Config"]["Env"] if e.split("=", 1)[0] in keys]
cmd = ["docker", "run", "-d", "--name", "ntrip-allinone", "--restart", "unless-stopped",
       "--add-host", "ntripcaster:127.0.0.1"]
for e in env: cmd += ["-e", e]
for b in info["HostConfig"]["Binds"]: cmd += ["-v", b]
for cp, hb in info["HostConfig"]["PortBindings"].items():
    cmd += ["-p", f'{hb[0]["HostPort"]}:{cp.split("/")[0]}']
cmd.append(f"ntrip-allinone:{tag}")
sh("docker", "rm", "-f", "ntrip-allinone-old")
sh("docker", "stop", "ntrip-allinone")
sh("docker", "update", "--restart", "no", "ntrip-allinone")
sh("docker", "rename", "ntrip-allinone", "ntrip-allinone-old")
if sh(*cmd).returncode:
    print("FEHLER -> Rollback")
    sh("docker", "rename", "ntrip-allinone-old", "ntrip-allinone")
    sh("docker", "update", "--restart", "unless-stopped", "ntrip-allinone")
    sh("docker", "start", "ntrip-allinone")
    sys.exit(1)
PY
echo "Fertig. Alten Container nach erfolgreichem Test entfernen: docker rm ntrip-allinone-old"
