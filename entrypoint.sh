#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 landwirt99
set -e

# Erzeugt users.aut/groups.aut/clientmounts.aut synchron aus der Backend-DB,
# BEVOR Supervisor den Caster startet. Verhindert eine Race-Condition, bei
# der der Caster beim allerersten Start noch die alten/leeren Auth-Dateien
# einliest, waehrend das Backend parallel (und ggf. zu spaet) seine eigenen
# schreibt.
python3 -c "
import sys
sys.path.insert(0, '/app')
import app
app.init_db()
app.generate_aut_files()
app.sync_caster_conf()
print('Auth-Dateien initialisiert.')
"

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ntrip.conf
