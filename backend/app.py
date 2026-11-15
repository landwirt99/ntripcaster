# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 landwirt99
"""
NTRIP Backend (S3) — Benutzerverwaltung -> .aut-Dateien -> Caster-Rehash

Minimaler Baustein fuer S3 aus dem Konzept: statt die .aut-Dateien von Hand
zu pflegen, verwaltet man Nutzer ueber eine kleine REST-API + SQLite-DB.
Jeder Request, der Nutzer aendert, schreibt automatisch neue
users.aut / groups.aut / clientmounts.aut und loest per HTTP
"http://caster/admin?mode=rehash" ein Rehash aus (laut Handbuch:
stoert laufende Streams NICHT).

Wichtiger, bewusster Kompromiss: Der BKG-Caster selbst kann nur Klartext-
oder crypt()-Passwoerter in users.aut pruefen (kein bcrypt/argon2). Deshalb
speichern wir die Rover-Passwoerter hier (in unserer eigenen, nur lokal
erreichbaren DB) im Klartext -- NICHT identisch mit irgendwelchen anderen
Accounts (z.B. agroaktiv) verwenden! Das Admin-Backend selbst ist per
ADMIN_TOKEN abgesichert.
"""

import os
import re
import hmac
import base64
import math
import socket
import time
import threading
import sqlite3
import requests
from datetime import datetime, date, timedelta, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, field_validator

DB_PATH = "/data/ntrip.db"
CONF_DIR = "/conf"
CASTER_URL = os.environ.get("CASTER_URL", "http://caster:80")
CASTER_ADMIN_USER = os.environ.get("CASTER_ADMIN_USER", "admin")
CASTER_ADMIN_PASS = os.environ.get("CASTER_ADMIN_PASS", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "changeme-admin-token")

def utcnow() -> datetime:
    """Naive UTC-Zeit (wie bisher in der DB gespeichert), ohne veraltetes utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@asynccontextmanager
async def lifespan(app_: FastAPI):
    startup()
    yield


app = FastAPI(title="NTRIP Backend (S3)", lifespan=lifespan)

# --- Sicherheit ----------------------------------------------------------
# /internal/* wird nur vom gga-proxy im selben Container (127.0.0.1) benutzt.
# Der Port 8000 ist aber nach aussen veroeffentlicht -> von dort NICHT erlauben.
def require_local(request: Request):
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=403, detail="internal endpoint")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Liefert Validierungsfehler als lesbaren String in 'detail' (die GUI zeigt ihn direkt an)."""
    msgs = []
    for e in exc.errors():
        m = str(e.get("msg", "")).replace("Value error, ", "")
        loc = ".".join(str(x) for x in e.get("loc", []) if x not in ("body", "query"))
        msgs.append(f"{loc}: {m}" if loc else m)
    return JSONResponse({"detail": "; ".join(msgs)}, status_code=422)


# Fehlversuche bei der Token-Pruefung pro Client-IP begrenzen (Brute-Force-Schutz)
AUTH_FAIL_LIMIT = 10
AUTH_FAIL_MIN_GAP = 3.0   # parallele Requests EINER Seite zaehlen zusammen als ein Fehlversuch
AUTH_FAIL_WINDOW = 300  # Sekunden
_AUTH_FAILS: dict = {}


@app.middleware("http")
async def auth_rate_limit(request: Request, call_next):
    path = request.url.path
    is_api = path.startswith("/api/")
    ip = request.client.host if request.client else "?"
    if is_api and ip not in ("127.0.0.1", "::1"):
        now = time.time()
        fails = [t for t in _AUTH_FAILS.get(ip, []) if now - t < AUTH_FAIL_WINDOW]
        if fails:
            _AUTH_FAILS[ip] = fails
        else:
            _AUTH_FAILS.pop(ip, None)
        if len(fails) >= AUTH_FAIL_LIMIT:
            return JSONResponse({"detail": "Zu viele Fehlversuche -- bitte einige Minuten warten"}, status_code=429)
    response = await call_next(request)
    if is_api and response.status_code == 401:
        if len(_AUTH_FAILS) > 1000:
            _AUTH_FAILS.clear()
        lst = _AUTH_FAILS.setdefault(ip, [])
        if not lst or time.time() - lst[-1] >= AUTH_FAIL_MIN_GAP:
            lst.append(time.time())
            if len(lst) == AUTH_FAIL_LIMIT:      # Schwelle erreicht -> Alarm (einmal je Sperre)
                threading.Thread(
                    target=create_system_alert,
                    args=("SYSTEM", f"GUI-Login: {AUTH_FAIL_LIMIT} Fehlversuche von {ip} -- IP fuer {AUTH_FAIL_WINDOW // 60} Min. gesperrt"),
                    kwargs={"kind": "gui_login"}, daemon=True).start()
    return response


# Eingabepruefung: Werte landen in users.aut / ntripcaster.conf (zeilenbasiert,
# ':' als Trenner) -> Doppelpunkt, Leerzeichen und Zeilenumbrueche wuerden die
# Dateien zerstoeren bzw. fremde Direktiven einschleusen.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
RESERVED_USERNAMES = {"admin", "oper", "firstadmin", "default"}
_BAD_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")


def _check_username(v: str) -> str:
    if not USERNAME_RE.match(v) or v.lower() in RESERVED_USERNAMES:
        raise ValueError("Benutzername: 3-32 Zeichen aus A-Z a-z 0-9 . _ - (nicht 'admin'/'oper'/'default')")
    return v


def _check_password(v: str) -> str:
    if not (6 <= len(v) <= 64) or ":" in v or _BAD_CHARS.search(v):
        raise ValueError("Passwort: 6-64 Zeichen, ohne Doppelpunkt, Leerzeichen und Steuerzeichen")
    return v


def _check_conf_user(v: str) -> str:
    if v and (":" in v or _BAD_CHARS.search(v)):
        raise ValueError("Benutzername ohne Doppelpunkt, Leerzeichen und Steuerzeichen")
    return v


def _check_conf_pass(v: str) -> str:
    if v and _BAD_CHARS.search(v):
        raise ValueError("Passwort ohne Leerzeichen und Steuerzeichen")
    return v


def _check_host(v: str) -> str:
    if not HOST_RE.match(v):
        raise ValueError("ungueltiger Hostname")
    return v


def _check_key(v: str) -> str:
    if not KEY_RE.match(v):
        raise ValueError("Name: 1-40 Zeichen aus A-Z a-z 0-9 . _ -")
    return v


def _check_port(v: int) -> int:
    if not (1 <= v <= 65535):
        raise ValueError("ungueltiger Port")
    return v


def db():
    # timeout: bei gleichzeitigen Schreibzugriffen (Threads/Requests) kurz warten statt "database is locked"
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            max_connections INTEGER NOT NULL DEFAULT 1,
            valid_from TEXT,
            valid_until TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS machine_status (
            username TEXT PRIMARY KEY,
            online INTEGER NOT NULL DEFAULT 0,
            online_since TEXT,
            last_seen TEXT,
            last_ip TEXT,
            last_mountpoint TEXT,
            last_requested_mountpoint TEXT,
            last_lat REAL,
            last_lon REAL,
            last_fix_quality INTEGER,
            last_sat_count INTEGER,
            last_distance_km REAL,
            last_pos_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS position_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            session_id TEXT,
            ts TEXT DEFAULT CURRENT_TIMESTAMP,
            lat REAL,
            lon REAL,
            fix_quality INTEGER,
            sat_count INTEGER
        )
        """
    )
    # Migration: session_id nachtraeglich ergaenzen, falls DB aus aelterer Version stammt
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(position_history)").fetchall()]
    if "session_id" not in cols:
        conn.execute("ALTER TABLE position_history ADD COLUMN session_id TEXT")

    cols = [r["name"] for r in conn.execute("PRAGMA table_info(machine_status)").fetchall()]
    if "last_requested_mountpoint" not in cols:
        conn.execute("ALTER TABLE machine_status ADD COLUMN last_requested_mountpoint TEXT")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            ip TEXT,
            mountpoint TEXT,
            started_at TEXT DEFAULT CURRENT_TIMESTAMP,
            ended_at TEXT
        )
        """
    )
    if "last_seen" not in [r["name"] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]:
        conn.execute("ALTER TABLE sessions ADD COLUMN last_seen TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            session1_id TEXT,
            session2_id TEXT,
            ip1 TEXT,
            ip2 TEXT,
            distance_m REAL,
            reason TEXT,
            detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            auto_kicked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS regional_stations (
            key TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            remote_mountpoint TEXT NOT NULL,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            is_failover INTEGER NOT NULL DEFAULT 0,
            caster_host TEXT,
            caster_port INTEGER,
            caster_user TEXT,
            caster_pass TEXT
        )
        """
    )
    # Erstbefuellung NUR bei leerer Tabelle: die DB ist die alleinige Quelle der
    # Wahrheit. Frueher lief hier zusaetzlich ein DELETE auf 'BS','MUC','WARN',
    # das von Hand vergebene Kurznamen bei JEDEM Start wieder geloescht hat.
    if conn.execute("SELECT COUNT(*) FROM regional_stations").fetchone()[0] == 0:
        for key, name, mp, lat, lon, en, fo in (
            ("WARN00DEU0", "Warnemuende", "WARN00DEU0", 54.17, 12.10, 0, 1),
            ("PTBB00DEU0", "Braunschweig-PTB", "PTBB00DEU0", 52.30, 10.46, 1, 0),
            ("OBE400DEU0", "Oberpfaffenhofen", "OBE400DEU0", 48.08, 11.28, 1, 0),
        ):
            conn.execute(
                "INSERT OR IGNORE INTO regional_stations (key, name, remote_mountpoint, lat, lon, enabled, is_failover) VALUES (?,?,?,?,?,?,?)",
                (key, name, mp, lat, lon, en, fo),
            )

    # Migration: caster_host/port/user/pass Spalten nachtraeglich ergaenzen,
    # falls DB aus aelterer Version stammt
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(regional_stations)").fetchall()]
    if "caster_host" not in cols:
        conn.execute("ALTER TABLE regional_stations ADD COLUMN caster_host TEXT")
        conn.execute("ALTER TABLE regional_stations ADD COLUMN caster_port INTEGER")
        conn.execute("ALTER TABLE regional_stations ADD COLUMN caster_user TEXT")
        conn.execute("ALTER TABLE regional_stations ADD COLUMN caster_pass TEXT")
    # Bestehende Stationen ohne eigene Caster-Angabe bekommen die urspruenglichen
    # EUREF-IP-Zugangsdaten zugewiesen (Standard-Seed-Stationen)
    conn.execute(
        "UPDATE regional_stations SET caster_host='euref-ip.net', caster_port=2101 WHERE caster_host IS NULL"
    )
    # Backup-Zuordnung: "backup_for" = lokaler Mountpoint (z.B. RTCM32 = Trimble oder
    # ein Stationsname), den diese Station ersetzt, solange er ausgefallen ist.
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(regional_stations)").fetchall()]
    if "backup_for" not in cols:
        conn.execute("ALTER TABLE regional_stations ADD COLUMN backup_for TEXT")
        conn.execute("UPDATE regional_stations SET backup_for='RTCM32' WHERE is_failover=1")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_position_history_ts ON position_history(ts)")
    # Einmalige Erstbefuellung aus den Umgebungsvariablen (Docker Compose),
    # danach ist die DB die alleinige Quelle der Wahrheit -- Aenderungen
    # ueber die GUI ueberleben also auch einen Container-Neustart.
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_token', ?)",
        (ADMIN_TOKEN,),
    )
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('caster_admin_pass', ?)",
        (CASTER_ADMIN_PASS,),
    )
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_grace_seconds', '60')")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_distance_m', '300')")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_auto_kick', 'false')")
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('alert_webhook_url', '')")
    # Caster-Verzeichnis: Zugangsdaten bleiben erhalten, auch wenn keine Station des Casters
    # (mehr) als Mountpoint angelegt ist.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS casters (
            host TEXT PRIMARY KEY,
            port INTEGER NOT NULL,
            user TEXT NOT NULL DEFAULT '',
            pass TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO casters (host, port, user, pass) "
        "SELECT caster_host, COALESCE(caster_port, 2101), COALESCE(caster_user, ''), COALESCE(caster_pass, '') "
        "FROM regional_stations WHERE caster_host IS NOT NULL GROUP BY caster_host"
    )
    eu = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'eurefip_%'").fetchall()}
    if eu.get("eurefip_host"):      # zuletzt in der GUI eingetragener Caster
        try:
            eu_port = int(eu.get("eurefip_port") or 2101)
        except ValueError:
            eu_port = 2101
        conn.execute("INSERT OR IGNORE INTO casters (host, port, user, pass) VALUES (?,?,?,?)",
                     (eu["eurefip_host"], eu_port, eu.get("eurefip_user", ""), eu.get("eurefip_pass", "")))
    conn.commit()
    conn.close()


# --- Systemeinstellungen (ueber die GUI aenderbar, in der DB gespeichert) ------------
SYSTEM_DEFAULTS = {
    "public_hostname": os.environ.get("PUBLIC_HOSTNAME", "ntrip.example.org"),
    "public_ntrip_port": int(os.environ.get("PUBLIC_NTRIP_PORT", "5000")),
    "near_recheck_s": 30.0,
    "near_min_dwell_s": 120.0,
    "near_hysteresis_km": 10.0,
    "failback_stable_s": 30.0,
    "failover_fail_threshold": 3,
    "failover_recover_threshold": 3,
    "retention_days": 365,
    "sourcetable_mode": "v1",
    "station_coverage_km": 30.0,
    "trimble_legacy": 1,       # 1 = Legacy-Strom /RTCM (RTCM 3.1) von der Trimble holen, 0 = nur /RTCM32
}


def get_sys(name: str):
    """Typisierter Wert einer Systemeinstellung (DB-Wert, sonst Standard)."""
    default = SYSTEM_DEFAULTS[name]
    raw = get_setting("sys_" + name)
    if raw == "":
        return default
    try:
        return type(default)(raw)
    except (TypeError, ValueError):
        return default


def get_all_sys() -> dict:
    return {k: get_sys(k) for k in SYSTEM_DEFAULTS}


class SystemSettingsIn(BaseModel):
    public_hostname: str | None = None
    public_ntrip_port: int | None = None
    near_recheck_s: float | None = None
    near_min_dwell_s: float | None = None
    near_hysteresis_km: float | None = None
    failback_stable_s: float | None = None
    failover_fail_threshold: int | None = None
    failover_recover_threshold: int | None = None
    retention_days: int | None = None
    sourcetable_mode: str | None = None
    station_coverage_km: float | None = None
    trimble_legacy: int | None = None

    @field_validator("public_hostname")
    @classmethod
    def _v_host(cls, v):
        return _check_host(v) if v is not None else v

    @field_validator("public_ntrip_port")
    @classmethod
    def _v_port(cls, v):
        return _check_port(v) if v is not None else v

    @field_validator("sourcetable_mode")
    @classmethod
    def _v_mode(cls, v):
        if v is not None and v not in ("v1", "v2"):
            raise ValueError("nur v1 oder v2 erlaubt")
        return v


SYSTEM_RANGES = {
    "near_recheck_s": (5, 3600), "near_min_dwell_s": (0, 86400), "near_hysteresis_km": (0, 1000),
    "failback_stable_s": (5, 3600), "failover_fail_threshold": (1, 20),
    "failover_recover_threshold": (1, 20), "retention_days": (7, 3650),
    "station_coverage_km": (1, 500), "trimble_legacy": (0, 1),
}


def _sys_ranges_ok(body: SystemSettingsIn):
    for k, (lo, hi) in SYSTEM_RANGES.items():
        v = getattr(body, k)
        if v is not None and not (lo <= v <= hi):
            raise HTTPException(status_code=422, detail=f"{k}: erlaubt {lo} bis {hi}")


@app.get("/api/system-settings")
def get_system_settings_api(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return get_all_sys()


@app.post("/api/system-settings")
def update_system_settings(body: SystemSettingsIn, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    _sys_ranges_ok(body)
    legacy_before = get_sys("trimble_legacy")
    for k, v in body.model_dump(exclude_none=True).items():
        set_setting("sys_" + k, str(v))
    resync = write_relay_config() if get_sys("trimble_legacy") != legacy_before else None   # Relay-Zeilen aendern sich
    return {"ok": True, "settings": get_all_sys(), "resync_status": resync}


@app.get("/internal/proxy-settings", dependencies=[Depends(require_local)])
def internal_proxy_settings():
    """Einstellungen, die der gga-proxy regelmaessig abholt."""
    a = get_all_sys()
    return {k: a[k] for k in ("near_recheck_s", "near_min_dwell_s", "near_hysteresis_km",
                              "failback_stable_s", "sourcetable_mode")}




def cleanup_old_data():
    """Loescht Positionsverlauf, beendete Sessions und geloeste Alarme aelter als 1 Jahr."""
    conn = db()
    try:
        days = get_sys("retention_days")
        cutoff_sql = f"-{days} days"
        n1 = conn.execute("DELETE FROM position_history WHERE ts < datetime('now', ?)", (cutoff_sql,)).rowcount
        cutoff_iso = (utcnow() - timedelta(days=days)).isoformat()
        n2 = conn.execute("DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?", (cutoff_iso,)).rowcount
        n3 = conn.execute("DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?", (cutoff_iso,)).rowcount
        conn.commit()
        if n1 or n2 or n3:
            print(f"[backend] Aufraeumen: {n1} Positionen, {n2} Sessions, {n3} Alarme geloescht", flush=True)
    finally:
        conn.close()


def retention_loop():
    while True:
        try:
            cleanup_old_data()
        except Exception as e:
            print(f"[backend] Fehler beim Aufraeumen: {e}", flush=True)
        time.sleep(6 * 3600)


# Einstellungen werden kurz im Speicher gehalten (jeder API-Aufruf prueft das Token und liest
# Einstellungen -> sonst je ein DB-Zugriff). TTL statt reiner Invalidierung, damit auch
# Aenderungen direkt in der DB nach wenigen Sekunden wirken.
_SETTINGS_TTL = 3.0
_settings_cache = {"ts": 0.0, "data": {}}


def _all_settings() -> dict:
    now = time.monotonic()
    if now - _settings_cache["ts"] > _SETTINGS_TTL:
        conn = db()
        try:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        finally:
            conn.close()
        _settings_cache["data"] = {r["key"]: r["value"] for r in rows}
        _settings_cache["ts"] = now
    return _settings_cache["data"]


def get_setting(key: str) -> str:
    return _all_settings().get(key, "")


def set_setting(key: str, value: str):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()
    finally:
        conn.close()
    _settings_cache["ts"] = 0.0


def check_token(x_admin_token: str | None):
    expected = get_setting("admin_token")
    if not x_admin_token or not hmac.compare_digest(x_admin_token.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="invalid admin token")


def user_is_currently_valid(row) -> bool:
    if not row["active"]:
        return False
    today = date.today().isoformat()
    if row["valid_from"] and today < row["valid_from"]:
        return False
    if row["valid_until"] and today > row["valid_until"]:
        return False
    return True


class UserIn(BaseModel):
    username: str
    password: str
    max_connections: int = 1
    valid_from: str | None = None
    valid_until: str | None = None

    @field_validator("username")
    @classmethod
    def _v_username(cls, v):
        return _check_username(v)

    @field_validator("password")
    @classmethod
    def _v_password(cls, v):
        return _check_password(v)

    @field_validator("max_connections")
    @classmethod
    def _v_maxconn(cls, v):
        if not (1 <= v <= 100):
            raise ValueError("max_connections: 1-100")
        return v


def generate_aut_files():
    conn = db()
    rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    conn.close()

    active_rows = []
    for r in rows:
        if not user_is_currently_valid(r):
            continue
        if not USERNAME_RE.match(r["username"]) or r["username"].lower() in RESERVED_USERNAMES \
                or ":" in r["password"] or _BAD_CHARS.search(r["password"]):
            print(f"[backend] Benutzer {r['username']!r} uebersprungen: ungueltige Zeichen in Name/Passwort", flush=True)
            continue
        active_rows.append(r)

    # users.aut -- Admin-User fest verdrahtet + alle aktiven Rover-User
    users_lines = ["# Automatisch generiert vom NTRIP-Backend (S3) - nicht manuell editieren!"]
    users_lines.append(f"admin:{get_setting('caster_admin_pass')}")
    for r in active_rows:
        users_lines.append(f"{r['username']}:{r['password']}")

    # groups.aut -- eine eigene Gruppe pro User mit Limit (Account-Sharing-Praevention)
    groups_lines = ["# Automatisch generiert vom NTRIP-Backend (S3) - nicht manuell editieren!"]
    # groups.aut -- "FirstAdmin" ist ein von NtripCaster FEST vorgegebener,
    # magischer Gruppenname (siehe Handbuch Kap. 8) fuer volle Admin-Rechte
    # ueber die Admin-Weboberflaeche (inkl. rehash). Ein frei gewaehlter Name
    # wie "admins" wird NICHT erkannt!
    groups_lines.append("FirstAdmin:admin")
    for r in active_rows:
        groups_lines.append(f"{r['username']}:{r['username']}:{r['max_connections']}")

    # clientmounts.aut -- /admin,/oper nur fuer FirstAdmin (voller Zugriff,
    # inkl. rehash); alle aktiven User-Gruppen duerfen per "default" auf alle
    # nicht anderweitig beschraenkten Mountpoints (also /RTCM und /RTCM32)
    group_names = ",".join(r["username"] for r in active_rows) if active_rows else ""
    clientmounts_lines = ["# Automatisch generiert vom NTRIP-Backend (S3) - nicht manuell editieren!"]
    clientmounts_lines.append("/admin:FirstAdmin")
    clientmounts_lines.append("/oper:FirstAdmin")
    clientmounts_lines.append(f"default:{group_names}")

    with open(os.path.join(CONF_DIR, "users.aut"), "w") as f:
        f.write("\n".join(users_lines) + "\n")
    with open(os.path.join(CONF_DIR, "groups.aut"), "w") as f:
        f.write("\n".join(groups_lines) + "\n")
    with open(os.path.join(CONF_DIR, "clientmounts.aut"), "w") as f:
        f.write("\n".join(clientmounts_lines) + "\n")


def trigger_rehash():
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "rehash"},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=5,
        )
        return r.status_code
    except Exception as e:
        return f"error: {e}"


def haversine_m(lat1, lon1, lat2, lon2) -> float:
    return haversine_km(lat1, lon1, lat2, lon2) * 1000.0


def get_caster_listeners():
    """Fragt den Caster nach aktuell verbundenen Clients (fuer Auto-Kick)."""
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "listeners", "nohtml": "1"},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=5,
        )
        listeners = []
        for line in r.text.splitlines():
            if "[Id:" not in line:
                continue
            def grab(key):
                m = re.search(rf"\[{key}: ([^\]]*)\]", line)
                return m.group(1) if m else None
            listeners.append({"user": grab("User"), "ip": grab("IP"), "id": grab("Id")})
        return listeners
    except Exception as e:
        log_alert_engine(f"Konnte Listeners nicht abfragen: {e}")
        return []


def kick_connection(conn_id: str):
    try:
        requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "kick", "argument": conn_id},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=5,
        )
        return True
    except Exception:
        return False


def notify_alert(alert: dict):
    webhook_url = get_setting("alert_webhook_url")
    if webhook_url:
        try:
            requests.post(webhook_url, json=alert, timeout=5)
        except Exception as e:
            log_alert_engine(f"Webhook-Benachrichtigung fehlgeschlagen: {e}")


def log_alert_engine(msg: str):
    print(f"[alert-engine] {msg}", flush=True)


def check_concurrent_sessions():
    """Hintergrund-Job (S7): erkennt, ob ein Login (user_id) gleichzeitig von
    zwei Orten aus genutzt wird (Account-Sharing). Regel siehe Konzept Kap. 5.5:
    >=2 Sessions gleichzeitig aktiv (Dauer jeweils > Karenzzeit) UND
    (Positionen > Distanz-Schwelle auseinander ODER (keine GGA) verschiedene IPs)."""
    conn = db()
    try:
        grace = int(float(get_setting("alert_grace_seconds") or 60))
        dist_threshold = float(get_setting("alert_distance_m") or 300)
        auto_kick = (get_setting("alert_auto_kick") or "false").lower() == "true"

        now = utcnow()
        close_stale_sessions(conn)
        open_sessions = conn.execute(
            "SELECT * FROM sessions WHERE ended_at IS NULL ORDER BY username"
        ).fetchall()

        by_user = {}
        for s in open_sessions:
            by_user.setdefault(s["username"], []).append(s)

        for username, sess_list in by_user.items():
            if len(sess_list) < 2:
                continue
            # Nur Sessions beruecksichtigen, die schon laenger als die Karenzzeit laufen
            stable = []
            for s in sess_list:
                started = datetime.fromisoformat(s["started_at"])
                if (now - started).total_seconds() > grace:
                    stable.append(s)
            if len(stable) < 2:
                continue

            for i in range(len(stable)):
                for j in range(i + 1, len(stable)):
                    s1, s2 = stable[i], stable[j]

                    # Bereits offener Alarm fuer dieses Sessionpaar? -> nicht doppelt anlegen
                    existing = conn.execute(
                        """
                        SELECT id FROM alerts WHERE resolved_at IS NULL AND username=?
                        AND ((session1_id=? AND session2_id=?) OR (session1_id=? AND session2_id=?))
                        """,
                        (username, s1["session_id"], s2["session_id"], s2["session_id"], s1["session_id"]),
                    ).fetchone()
                    if existing:
                        continue

                    pos1 = conn.execute(
                        "SELECT lat, lon FROM position_history WHERE session_id=? ORDER BY ts DESC LIMIT 1",
                        (s1["session_id"],),
                    ).fetchone()
                    pos2 = conn.execute(
                        "SELECT lat, lon FROM position_history WHERE session_id=? ORDER BY ts DESC LIMIT 1",
                        (s2["session_id"],),
                    ).fetchone()

                    reason = None
                    distance_m = None
                    if pos1 and pos2:
                        distance_m = round(haversine_m(pos1["lat"], pos1["lon"], pos2["lat"], pos2["lon"]), 1)
                        if distance_m > dist_threshold:
                            reason = f"Positionen {distance_m} m auseinander (Schwelle {dist_threshold} m)"
                    else:
                        if s1["ip"] and s2["ip"] and s1["ip"] != s2["ip"]:
                            reason = f"Keine GGA-Daten, aber unterschiedliche IPs ueber > {grace}s parallel ({s1['ip']} / {s2['ip']})"

                    if not reason:
                        continue

                    detected_at = now.isoformat()
                    cur = conn.execute(
                        """
                        INSERT INTO alerts (username, session1_id, session2_id, ip1, ip2, distance_m, reason, detected_at)
                        VALUES (?,?,?,?,?,?,?,?)
                        """,
                        (username, s1["session_id"], s2["session_id"], s1["ip"], s2["ip"], distance_m, reason, detected_at),
                    )
                    alert_id = cur.lastrowid
                    conn.commit()
                    log_alert_engine(f"ALARM concurrent_login user={username} {reason}")

                    auto_kicked = False
                    if auto_kick:
                        listeners = get_caster_listeners()
                        for l in listeners:
                            if l["user"] == username and l["ip"] in (s1["ip"], s2["ip"]):
                                kick_connection(l["id"])
                                auto_kicked = True
                        if auto_kicked:
                            conn.execute("UPDATE users SET active=0 WHERE username=?", (username,))
                            conn.execute("UPDATE alerts SET auto_kicked=1 WHERE id=?", (alert_id,))
                            conn.commit()
                            generate_aut_files()
                            trigger_rehash()
                            log_alert_engine(f"Auto-Kick + Sperre ausgefuehrt fuer user={username}")

                    notify_alert({
                        "type": "concurrent_login",
                        "username": username,
                        "reason": reason,
                        "distance_m": distance_m,
                        "ip1": s1["ip"], "ip2": s2["ip"],
                        "detected_at": detected_at,
                        "auto_kicked": auto_kicked,
                    })

        # Alte offene Alarme automatisch aufloesen, wenn eine der beiden Sessions
        # inzwischen beendet wurde (Entprellung / Ende protokollieren)
        open_alerts = conn.execute("SELECT * FROM alerts WHERE resolved_at IS NULL").fetchall()
        for a in open_alerts:
            s1 = conn.execute("SELECT ended_at FROM sessions WHERE session_id=?", (a["session1_id"],)).fetchone()
            s2 = conn.execute("SELECT ended_at FROM sessions WHERE session_id=?", (a["session2_id"],)).fetchone()
            if (s1 and s1["ended_at"]) or (s2 and s2["ended_at"]):
                conn.execute("UPDATE alerts SET resolved_at=? WHERE id=?", (now.isoformat(), a["id"]))
                conn.commit()
    finally:
        conn.close()


def alert_engine_loop():
    while True:
        try:
            check_concurrent_sessions()
        except Exception as e:
            log_alert_engine(f"Fehler im Alarm-Check: {e}")
        time.sleep(20)


def startup():
    init_db()
    generate_aut_files()
    threading.Thread(target=alert_engine_loop, daemon=True).start()
    threading.Thread(target=failover_loop, daemon=True).start()
    threading.Thread(target=retention_loop, daemon=True).start()


@app.get("/api/users")
def list_users(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    rows = conn.execute("SELECT id, username, password, active, max_connections, valid_from, valid_until, created_at FROM users ORDER BY username").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/users")
def create_user(user: UserIn, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, max_connections, valid_from, valid_until) VALUES (?,?,?,?,?)",
            (user.username, user.password, user.max_connections, user.valid_from, user.valid_until),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="username already exists")
    conn.close()
    generate_aut_files()
    rehash_result = trigger_rehash()
    return {"ok": True, "rehash": rehash_result}


@app.delete("/api/users/{username}")
def delete_user(username: str, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.execute("DELETE FROM machine_status WHERE username=?", (username,))
    conn.commit()
    conn.close()
    generate_aut_files()
    rehash_result = trigger_rehash()
    return {"ok": True, "rehash": rehash_result}


class UserPatch(BaseModel):
    active: bool | None = None
    password: str | None = None
    max_connections: int | None = None
    valid_from: str | None = None
    valid_until: str | None = None

    @field_validator("password")
    @classmethod
    def _v_password(cls, v):
        return _check_password(v) if v is not None else v

    @field_validator("max_connections")
    @classmethod
    def _v_maxconn(cls, v):
        if v is not None and not (1 <= v <= 100):
            raise ValueError("max_connections: 1-100")
        return v


@app.patch("/api/users/{username}")
def patch_user(username: str, patch: UserPatch, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="not found")
    fields = patch.model_dump(exclude_unset=True)
    if fields:
        set_clause = ", ".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE users SET {set_clause} WHERE username=?", (*fields.values(), username))
        conn.commit()
    conn.close()
    generate_aut_files()
    rehash_result = trigger_rehash()
    return {"ok": True, "rehash": rehash_result}


@app.post("/api/rehash")
def manual_rehash(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    generate_aut_files()
    return {"ok": True, "rehash": trigger_rehash()}


class TokenChange(BaseModel):
    current_token: str
    new_token: str


@app.post("/api/settings/admin-token")
def change_admin_token(body: TokenChange):
    """Aendert das Login-Token der Web-Oberflaeche (GUI-Login)."""
    if not hmac.compare_digest(body.current_token.encode(), get_setting("admin_token").encode()):
        raise HTTPException(status_code=401, detail="invalid current token")
    if not body.new_token or len(body.new_token) < 6:
        raise HTTPException(status_code=400, detail="new token too short (min. 6 chars)")
    set_setting("admin_token", body.new_token)
    return {"ok": True}


class CasterPasswordChange(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _v_pw(cls, v):
        return _check_password(v)


@app.post("/api/settings/caster-admin-password")
def change_caster_admin_password(body: CasterPasswordChange, x_admin_token: str | None = Header(default=None)):
    """Aendert das Passwort des 'admin'-Users im Caster selbst (users.aut) und
    loest sofort einen Rehash aus, damit das Backend danach weiterhin mit dem
    Caster sprechen kann.

    Wichtig: Der laufende Caster-Prozess hat bis zum erfolgreichen Rehash noch
    das ALTE Passwort im Speicher -- der Rehash-Request selbst muss daher noch
    mit dem alten Passwort authentifiziert werden, obwohl die Datei schon das
    neue enthaelt. Erst danach gilt das neue Passwort."""
    check_token(x_admin_token)
    if not body.new_password or len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="new password too short (min. 6 chars)")
    old_password = get_setting("caster_admin_pass")
    set_setting("caster_admin_pass", body.new_password)
    generate_aut_files()
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "rehash"},
            auth=(CASTER_ADMIN_USER, old_password),
            timeout=5,
        )
        rehash_result = r.status_code
    except Exception as e:
        rehash_result = f"error: {e}"
    time.sleep(1)
    return {"ok": True, "rehash": rehash_result, "verified": caster_admin_login_ok()}


# --- Caster-Zugang -----------------------------------------------------------------------

def caster_resync():
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "resync"},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=15,
        )
        return r.status_code
    except Exception as e:
        log_alert_engine(f"Resync fehlgeschlagen: {e}")
        return None


def caster_admin_login_ok() -> bool:
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "sources", "nohtml": "1"},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False


@app.get("/api/security-status")
def security_status(x_admin_token: str | None = Header(default=None)):
    """Zustand der Zugangsdaten (ohne die Passwoerter selbst auszugeben)."""
    check_token(x_admin_token)
    return {
        "gui_token_default": hmac.compare_digest(get_setting("admin_token").encode(), b"changeme-admin-token"),
        "caster_admin_ok": caster_admin_login_ok(),
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "time": utcnow().isoformat()}


# --- S5: GGA / Maschinen-Status --------------------------------------------

# Referenzkoordinate der Basisstation (Trimble BD982) fuer die Distanz-Anzeige.
# Wird jetzt automatisch vom gga-proxy aus dem RTCM-Strom selbst (Msg 1005/1006)
# ausgelesen und in "settings" hinterlegt -- die ENV-Werte sind nur ein
# Fallback, solange noch keine Live-Koordinate erkannt wurde.
BASE_LAT_FALLBACK = float(os.environ.get("BASE_LAT", "54.17"))
BASE_LON_FALLBACK = float(os.environ.get("BASE_LON", "12.10"))


def get_base_position():
    lat = get_setting("base_lat")
    lon = get_setting("base_lon")
    if lat and lon:
        return float(lat), float(lon)
    return BASE_LAT_FALLBACK, BASE_LON_FALLBACK


class BasePosition(BaseModel):
    lat: float
    lon: float


@app.post("/internal/base-position", dependencies=[Depends(require_local)])
def base_position(pos: BasePosition):
    """Wird vom gga-proxy aufgerufen, sobald er die Basiskoordinate direkt aus
    dem RTCM-1005/1006-Strom der Trimble BD982 dekodiert hat."""
    set_setting("base_lat", str(pos.lat))
    set_setting("base_lon", str(pos.lon))
    return {"ok": True}


@app.get("/api/base-position")
def get_base_position_api(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    lat, lon = get_base_position()
    return {"lat": lat, "lon": lon, "source": "rtcm-1005/1006" if get_setting("base_lat") else "fallback"}


@app.get("/internal/near-candidates", dependencies=[Depends(require_local)])
def near_candidates():
    """Fuer den gga-proxy: Liste aller /NEAR-Kandidaten (eigene Basis +
    aktivierte Regional-Stationen) mit Koordinaten. Kein Admin-Token noetig,
    da nur intern im Docker-Netz/localhost aufgerufen."""
    lat, lon = get_base_position()
    pure = get_pure_backups()
    candidates = {"/RTCM32": [lat, lon]}
    for s in get_all_regional_stations():
        if s["enabled"] and s["key"] not in pure:
            candidates[f"/{s['key']}"] = [s["lat"], s["lon"]]
    return candidates


# --- S8: Backup-Quelle & Failover (EUREF WARN00DEU) ------------------------
#
# Primaerquelle: Trimble BD982 (lokal, z.B. 192.168.0.10:28001/28002).
# Backupquelle: BKG EUREF-IP-Caster, Mountpoint WARN00DEU0 (Warnemuende, RTCM
# 3.3 MSM) -- liegt auf fast identischer Koordinate wie unsere Basis.
#
# Scope-Einschraenkung (bewusst, siehe Konzept S8): Nur /RTCM32 bekommt ein
# Backup (reiner relay pull, kein Formatumbau noetig). /RTCM (legacy
# RTCM3.1/1004/1012) bleibt ohne Transcoder bei Ausfall schlicht offline --
# ein MSM->Legacy-Transcoder (RTKLIB/BNC) ist eine eigene Baustelle und hier
# nicht implementiert.
#
# Umschalten erfordert laut Handbuch einen "resync" (kompletter Neustart des
# Caster-Prozesses, alle Streams kurz weg, 20-60s) -- daher Hysterese, um
# nicht bei jedem kurzen Flackern hin- und herzuschalten.

CONF_PATH = os.path.join(CONF_DIR, "ntripcaster.conf")
FAILOVER_CHECK_INTERVAL = 15    # Sekunden zwischen Healthchecks

_failover_state = {
    "mappings": [],
    "using_backup": False,
    "last_check": None,
    "last_switch": None,
}


def get_failover_settings():
    return {
        "eurefip_host": get_setting("eurefip_host") or "euref-ip.net",
        "eurefip_port": int(get_setting("eurefip_port") or "2101"),
        "eurefip_user": get_setting("eurefip_user") or "",
        "eurefip_pass": get_setting("eurefip_pass") or "",
    }


def get_all_regional_stations():
    conn = db()
    rows = conn.execute("SELECT * FROM regional_stations ORDER BY name").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["backup_for"] = (d.get("backup_for") or "") or None
        result.append(d)
    return result


def parse_euref_sourcetable_line(line: str):
    """Parst eine STR-Zeile der NTRIP-Sourcetable (Format siehe RTCM-Standard)."""
    if not line.startswith("STR;"):
        return None
    f = line.split(";")
    if len(f) < 10:
        return None
    try:
        return {
            "mountpoint": f[1],
            "identifier": f[2],
            "format": f[3],
            "nav_system": f[6],
            "country": f[8],
            "lat": float(f[9]),
            "lon": float(f[10]),
        }
    except (ValueError, IndexError):
        return None


NTRIP_USER_AGENT = "NTRIP NtripBackend/1.0"


def fetch_sourcetable_text(host: str, port: int, timeout: float = 10.0, max_bytes: int = 4_000_000) -> str:
    """Holt die Sourcetable eines NTRIP-Casters per Rohsocket. Noetig, weil manche Caster
    (z.B. ergnss-tr.ign.es) ohne NTRIP-User-Agent nur eine HTML-Seite liefern und andere
    mit "SOURCETABLE 200 OK" statt HTTP antworten (das versteht die requests-Bibliothek nicht)."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nNtrip-Version: Ntrip/2.0\r\n"
                   f"User-Agent: {NTRIP_USER_AGENT}\r\nConnection: close\r\n\r\n").encode())
        buf = bytearray()
        while len(buf) < max_bytes:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            buf.extend(d)
            if b"ENDSOURCETABLE" in buf:
                break
    raw = bytes(buf)
    head, sep, body = raw.partition(b"\r\n\r\n")
    if sep and b"transfer-encoding: chunked" in head.lower():
        out, pos = bytearray(), 0
        while pos < len(body):
            eol = body.find(b"\r\n", pos)
            if eol < 0:
                break
            try:
                size = int(body[pos:eol].split(b";")[0].strip() or b"0", 16)
            except ValueError:
                break
            if size == 0:
                break
            out.extend(body[eol + 2:eol + 2 + size])
            pos = eol + 2 + size + 2
        body = bytes(out)
    return (body if sep else raw).decode("latin-1", errors="replace")


def parse_sourcetable_stations(text: str) -> list:
    stations = []
    for line in text.replace("\r", "").split("\n"):
        parsed = parse_euref_sourcetable_line(line.strip())
        if parsed:
            stations.append(parsed)
    return stations


def fetch_euref_sourcetable(host: str | None = None, port: int | None = None):
    """Komplette, oeffentlich lesbare Sourcetable des konfigurierten Casters (EUREF-IP,
    IGN, RTK2go ...); Zugangsdaten sind nur fuer den eigentlichen Datenstream noetig."""
    settings = get_failover_settings()
    return parse_sourcetable_stations(fetch_sourcetable_text(host or settings["eurefip_host"],
                                                             port or settings["eurefip_port"]))


def get_regional_stations():
    """Aktivierte Regional-Stationen (Checkbox 'Als Mountpoint aktivieren' in
    der GUI) -- werden als eigene, dauerhafte Mountpoints relayed UND gehen
    in die /NEAR-Auswahl mit ein. Jede Station hat ihre EIGENEN Caster-
    Zugangsdaten (Host/Port/User/Pass) gespeichert, damit man Stationen von
    verschiedenen Castern (z.B. EUREF-IP + RTK2go) gleichzeitig nutzen kann."""
    conn = db()
    # Backup-Stationen werden immer mitgeholt (relay pull), damit sie bei einem
    # Ausfall der Primaerquelle sofort bereitstehen.
    rows = conn.execute(
        "SELECT * FROM regional_stations WHERE enabled=1 OR COALESCE(backup_for,'') != ''"
    ).fetchall()
    conn.close()
    return [
        {
            "mountpoint": f"/{r['key']}",
            "remote_mountpoint": r["remote_mountpoint"],
            "caster_host": r["caster_host"],
            "caster_port": r["caster_port"],
            "caster_user": r["caster_user"] or "",
            "caster_pass": r["caster_pass"] or "",
        }
        for r in rows
    ]


SOURCETABLE_PATH = os.path.join(CONF_DIR, "sourcetable.dat")


PROTECTED_STR = {"RTCM", "RTCM32", "NEAR"}


def get_pure_backups() -> set:
    """Stationen, die NUR als Ersatz dienen (backup_for gesetzt und niemand verlaesst sich
    auf sie als Primaerquelle). Sie bleiben unsichtbar fuer Rover. Gegenseitige Backups
    (z.B. AUG <-> MUC) sind dagegen normale, sichtbare Mountpoints."""
    stations = get_all_regional_stations()
    primaries = {s["backup_for"] for s in stations if s.get("backup_for")}
    return {s["key"] for s in stations if s.get("backup_for") and s["key"] not in primaries}


def sync_sourcetable():
    """Gleicht die STR-Zeilen in sourcetable.dat mit den Stationen aus der DB ab:
    aktive, sichtbare Stationen bekommen eine Zeile (Name/Position werden aktualisiert,
    NMEA-Flag 1 -> die App sendet GGA), Zeilen von umbenannten/geloeschten Stationen und
    reinen Backups verschwinden. RTCM, RTCM32 und NEAR bleiben unangetastet."""
    try:
        with open(SOURCETABLE_PATH, encoding="latin-1") as f:
            old_lines = f.read().splitlines()
    except OSError:
        return
    pure = get_pure_backups()
    visible = {st["key"]: st for st in get_all_regional_stations() if st["enabled"] and st["key"] not in pure}
    new_lines, seen = [], set()
    for l in old_lines:
        if not (l.startswith("STR;") and l.count(";") >= 2):
            new_lines.append(l)
            continue
        f = l.split(";")
        key = f[1]
        if key in PROTECTED_STR:
            new_lines.append(l)
        elif key in visible:
            st = visible[key]
            if len(f) > 11:
                f[2] = re.sub(r"[;\r\n]", " ", st["name"])[:60]
                f[9], f[10], f[11] = f"{st['lat']:.2f}", f"{st['lon']:.2f}", "1"
            new_lines.append(";".join(f))
            seen.add(key)
        # sonst: Zeile gehoert zu keiner aktiven Station mehr -> weglassen
    for key, st in visible.items():
        if key in seen:
            continue
        name = re.sub(r"[;\r\n]", " ", st["name"])[:60]
        new_lines.append(
            f"STR;{key};{name};RTCM 3.3;1006(10),1033(10),1077(1),1087(1),1097(1),1127(1),1230(10);"
            f"2;GPS+GLO+GAL+BDS;EigenerCaster;DEU;{st['lat']:.2f};{st['lon']:.2f};1;0;{st['remote_mountpoint']};none;B;N;3600;"
            f"{st.get('caster_host') or ''} Relay"
        )
    if new_lines != old_lines:
        with open(SOURCETABLE_PATH, "w", encoding="latin-1") as f:
            f.write("\n".join(new_lines) + "\n")
        log_alert_engine("sourcetable.dat mit den Stationen abgeglichen")


def write_relay_config():
    """Schreibt die 'relay pull'-Zeilen in ntripcaster.conf um:
    - Primaerquelle Trimble/GNSS-Basis (/RTCM, /RTCM32)
    - Alle aktiven Regional-Stationen und alle Backup-Stationen, jede mit ihren
      EIGENEN Caster-Zugangsdaten
    und loest danach einen 'resync' aus. Das Umschalten auf ein Backup passiert
    NICHT mehr hier, sondern pro Verbindung im gga-proxy (kein Caster-Neustart)."""
    trimble = get_trimble_settings()

    with open(CONF_PATH) as f:
        lines = f.readlines()

    block = []
    if get_sys("trimble_legacy"):
        block.append(f"relay pull -m /RTCM    {trimble['host']}:{trimble['port_legacy']}\n")
    block.append(f"relay pull -m /RTCM32  {trimble['host']}:{trimble['port_msm']}\n")
    for station in get_regional_stations():
        if station["caster_host"]:
            block.append(
                f"relay pull -i {station['caster_user']}:{station['caster_pass']} "
                f"-m {station['mountpoint']}  {station['caster_host']}:{station['caster_port']}/{station['remote_mountpoint']}\n"
            )

    new_lines = []
    inserted = False
    for line in lines:
        if line.strip().startswith("relay pull"):
            if not inserted:
                new_lines.extend(block)
                inserted = True
            continue        # weitere alte relay-Zeilen ueberspringen
        new_lines.append(line)
    if not inserted:        # noch keine relay-Zeile vorhanden -> Block anhaengen
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.extend(block)

    with open(CONF_PATH, "w") as f:
        f.writelines(new_lines)

    sync_sourcetable()
    return caster_resync()


# --- Failover-Zuordnung (Primaer -> Backup) ---------------------------------------
# Jede Station (auch die Trimble = "RTCM32") kann ein oder mehrere Backup-Stationen
# haben. Solange die Primaerquelle live ist, wird das Backup ignoriert. Faellt sie
# aus (oder wird manuell abgeschaltet), routet der gga-proxy neue Verbindungen auf
# das Backup und holt die Rover zurueck, sobald die Primaerquelle stabil wieder da ist.

def get_failover_map() -> dict:
    result = {}
    for s_ in get_all_regional_stations():
        bf = (s_.get("backup_for") or "").strip()
        if not bf or bf == s_["key"]:
            continue
        result.setdefault("/" + bf, []).append("/" + s_["key"])
    return result


def get_forced_primaries() -> list:
    return [m for m in (get_setting("failover_forced") or "").split(",") if m]


_sources_cache = {"ts": 0.0, "data": None}


def get_source_stats():
    """Verbundene Quellen laut Caster-Admin: {Mountpoint: KBytes gelesen} oder None, wenn der Caster
    nicht antwortet. 3 s gecacht (Proxy, Failover-Check, Trimble-Check und GUI fragen sonst einzeln).
    Die Trimble wird dafuer NICHT angefasst: der Caster haelt ohnehin je Strom eine Verbindung."""
    now = time.monotonic()
    if now - _sources_cache["ts"] < 3.0:
        return _sources_cache["data"]
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "sources", "nohtml": "1"},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=5,
        )
        data = None
        if r.status_code == 200:
            data = {}
            for line in r.text.splitlines():
                m = re.search(r"\[Mountpoint: ([^\]]*)\]", line)
                if m:
                    k = re.search(r"\[KBytes read: (\d+)\]", line)
                    data[m.group(1)] = int(k.group(1)) if k else 0
    except Exception:
        data = None
    _sources_cache.update(ts=now, data=data)
    return data


def get_live_mountpoints():
    """Mountpoints mit aktuell verbundener Quelle oder None."""
    stats = get_source_stats()
    return None if stats is None else set(stats)


def create_system_alert(username: str, reason: str, kind: str = "failover", tag: str | None = None):
    """Legt einen Systemalarm an. `tag` (in session1_id) erlaubt, ihn spaeter automatisch zu beenden;
    `kind` ist der Typ in der Webhook-Meldung."""
    conn = db()
    conn.execute(
        "INSERT INTO alerts (username, session1_id, reason, detected_at) VALUES (?,?,?,?)",
        (username, tag, reason, utcnow().isoformat()),
    )
    conn.commit()
    conn.close()
    notify_alert({"type": kind, "username": username, "reason": reason, "detected_at": utcnow().isoformat()})


def resolve_alerts_by_tag(tag: str):
    conn = db()
    try:
        conn.execute("UPDATE alerts SET resolved_at=? WHERE session1_id=? AND resolved_at IS NULL",
                     (utcnow().isoformat(), tag))
        conn.commit()
    finally:
        conn.close()


_failover_primary_state: dict = {}


def failover_health_check():
    """Ueberwacht alle Primaer->Backup-Paare (nur Status/Alarme; geroutet wird im Proxy)."""
    _failover_state["last_check"] = utcnow().isoformat()
    live = get_live_mountpoints()
    if live is None:
        return
    fmap = get_failover_map()
    forced = set(get_forced_primaries())

    mappings = []
    for primary, backups in fmap.items():
        st = _failover_primary_state.setdefault(primary, {"down": 0, "up": 0, "active": False})
        primary_up = primary in live and primary not in forced
        if primary_up:
            st["up"] += 1
            st["down"] = 0
        else:
            st["down"] += 1
            st["up"] = 0
        live_backups = [b for b in backups if b in live]
        target = live_backups[0] if live_backups else None

        if not st["active"] and st["down"] >= get_sys("failover_fail_threshold"):
            st["active"] = True
            _failover_state["last_switch"] = utcnow().isoformat()
            why = "manuell abgeschaltet" if primary in forced else "ausgefallen"
            msg = f"Failover aktiv: {primary} {why}, " + (f"{target} uebernimmt" if target else "KEIN Backup verfuegbar")
            log_alert_engine(msg)
            create_system_alert("SYSTEM", msg)
        elif st["active"] and st["up"] >= get_sys("failover_recover_threshold"):
            st["active"] = False
            _failover_state["last_switch"] = utcnow().isoformat()
            msg = f"Failover beendet: {primary} wieder verfuegbar"
            log_alert_engine(msg)
            create_system_alert("SYSTEM", msg)

        mappings.append({
            "primary": primary, "backups": backups, "primary_live": primary in live,
            "forced": primary in forced, "active": st["active"], "serving": (target if st["active"] else primary),
        })
    for gone in set(_failover_primary_state) - set(fmap):
        _failover_primary_state.pop(gone, None)
    _failover_state["mappings"] = mappings
    _failover_state["using_backup"] = any(m["active"] for m in mappings if m["primary"] == "/RTCM32")


_trimble_state = {"down": False, "fail": 0, "ok": 0, "since": None, "last_check": None, "reachable": None, "kb": {}}


def trimble_health_check():
    """Prueft die Basisstation OHNE eigene Verbindungen zu ihr: der Caster haelt je Strom eine
    dauerhafte Relay-Verbindung (unabhaengig von der Zahl der Rover). Problem = Strom nicht verbunden
    oder seit der letzten Pruefung keine neuen Daten. Alarm nach `failover_fail_threshold` Pruefungen in
    Folge (15 s Takt); endet automatisch nach `failover_recover_threshold` guten Pruefungen."""
    stats = get_source_stats()
    if stats is None:
        return                      # Caster selbst antwortet nicht -> kein Urteil ueber die Trimble
    st = _trimble_state
    mps = ["/RTCM32"] + (["/RTCM"] if get_sys("trimble_legacy") else [])
    not_connected = [mp for mp in mps if mp not in stats]
    stalled = [mp for mp in mps if mp in stats and mp in st["kb"] and stats[mp] == st["kb"][mp]]
    st["kb"] = {mp: stats[mp] for mp in mps if mp in stats}
    ok = not not_connected and not stalled
    st["last_check"] = utcnow().isoformat()
    st["reachable"] = ok
    if ok:
        st["ok"] += 1
        st["fail"] = 0
    else:
        st["fail"] += 1
        st["ok"] = 0
    trimble = get_trimble_settings()
    if not st["down"] and st["fail"] >= get_sys("failover_fail_threshold"):
        st["down"], st["since"] = True, utcnow().isoformat()
        if not_connected:
            msg = f"Trimble nicht erreichbar: {trimble['host']} ({', '.join(not_connected)} nicht verbunden)"
        else:
            msg = f"Trimble sendet keine Daten: {trimble['host']} ({', '.join(stalled)})"
        log_alert_engine(msg)
        create_system_alert("SYSTEM", msg, kind="trimble_down", tag="trimble-down")
    elif st["down"] and st["ok"] >= get_sys("failover_recover_threshold"):
        st["down"], st["since"] = False, None
        log_alert_engine("Trimble wieder erreichbar")
        resolve_alerts_by_tag("trimble-down")
        notify_alert({"type": "trimble_up", "username": "SYSTEM",
                      "reason": f"Trimble wieder erreichbar: {trimble['host']}", "detected_at": utcnow().isoformat()})


_caster_wd = {"fail": 0}
CASTER_WATCHDOG_FAILS = 4          # x 15 s ohne Antwort -> Prozess neu starten


def caster_responds() -> bool:
    """Antwortet die Caster-Verwaltung (irgendeine HTTP-Antwort zaehlt, auch 401)? Ungecacht."""
    try:
        requests.get(f"{CASTER_URL}/admin", params={"mode": "sources", "nohtml": "1"},
                     auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")), timeout=3)
        return True
    except Exception:
        return False


def restart_caster_process() -> bool:
    """Beendet den haengenden Caster-Prozess hart; Supervisor startet ihn automatisch neu."""
    killed = False
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline").read().replace("\0", " ")
        except OSError:
            continue
        if "ntripdaemon" in cmd:
            try:
                os.kill(int(pid), 9)
                killed = True
            except OSError:
                pass
    return killed


def caster_watchdog():
    """Der Caster kann sich bei einem Resync aufhaengen (Prozess lebt, antwortet aber nicht mehr, alle Rover
    getrennt). Antwortet er ~1 Minute lang nicht, wird der Prozess neu gestartet und ein Alarm angelegt."""
    if caster_responds():
        _caster_wd["fail"] = 0
        return
    _caster_wd["fail"] += 1
    if _caster_wd["fail"] >= CASTER_WATCHDOG_FAILS:
        _caster_wd["fail"] = 0
        if restart_caster_process():
            msg = "Caster antwortete nicht mehr und wurde automatisch neu gestartet"
            log_alert_engine(msg)
            create_system_alert("SYSTEM", msg, kind="caster_restart")


def failover_loop():
    while True:
        try:
            caster_watchdog()
        except Exception as e:
            log_alert_engine(f"Fehler im Caster-Watchdog: {e}")
        try:
            failover_health_check()
        except Exception as e:
            log_alert_engine(f"Fehler im Failover-Check: {e}")
        try:
            trimble_health_check()
        except Exception as e:
            log_alert_engine(f"Fehler im Trimble-Check: {e}")
        time.sleep(FAILOVER_CHECK_INTERVAL)


class FailoverSettings(BaseModel):
    eurefip_host: str | None = None
    eurefip_port: int | None = None
    eurefip_user: str | None = None
    eurefip_pass: str | None = None

    @field_validator("eurefip_host")
    @classmethod
    def _v_host(cls, v):
        return _check_host(v) if v else v

    @field_validator("eurefip_port")
    @classmethod
    def _v_port(cls, v):
        return _check_port(v) if v is not None else v

    @field_validator("eurefip_user")
    @classmethod
    def _v_user(cls, v):
        return _check_conf_user(v) if v else v

    @field_validator("eurefip_pass")
    @classmethod
    def _v_pass(cls, v):
        return _check_conf_pass(v) if v else v


@app.get("/api/failover-settings")
def get_failover_settings_api(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return get_failover_settings()


@app.post("/api/failover-settings")
def update_failover_settings(body: FailoverSettings, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    if body.eurefip_host is not None:
        set_setting("eurefip_host", body.eurefip_host)
    if body.eurefip_port is not None:
        set_setting("eurefip_port", str(body.eurefip_port))
    if body.eurefip_user is not None:
        set_setting("eurefip_user", body.eurefip_user)
    if body.eurefip_pass is not None:
        set_setting("eurefip_pass", body.eurefip_pass)
    return {"ok": True}


@app.get("/api/failover-status")
def get_failover_status(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return {**_failover_state, "trimble": _trimble_state}


def ntrip_probe(host: str, port: int, mountpoint: str, user: str, password: str, timeout: float = 6.0):
    """Fordert einen Mountpoint mit Basic-Auth an; liefert (ok, erste Antwortzeile)."""
    auth = ""
    if user:
        auth = "Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() + "\r\n"
    req = (f"GET /{mountpoint} HTTP/1.1\r\nHost: {host}:{port}\r\nNtrip-Version: Ntrip/2.0\r\n"
           f"User-Agent: NTRIP TestClient/1.0\r\n{auth}Connection: close\r\n\r\n").encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        first = s.recv(512).split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    ok = first.startswith("ICY 200") or (first.startswith("HTTP/1") and " 200" in first)
    return ok, first


def test_caster_credentials(host: str, port: int, user: str, password: str):
    """Testet Zugangsdaten gegen einen beliebigen Caster (NTRIP-typische Header, siehe
    fetch_sourcetable_text): holt die Sourcetable und fordert bis zu 10 Mountpoints an."""
    try:
        stations = parse_sourcetable_stations(fetch_sourcetable_text(host, port))
    except Exception as e:
        return {"ok": False, "error": f"Sourcetable nicht erreichbar: {e}"}

    stations = [s for s in stations if re.match(r"^[A-Za-z0-9._-]{1,60}$", s["mountpoint"])]
    if not stations:
        return {"ok": False, "error": "Keine Stationen auf diesem Caster gefunden"}

    last_status = None
    for station in stations[:10]:
        try:
            ok, first = ntrip_probe(host, port, station["mountpoint"], user, password)
            last_status = first
            if ok:
                return {"ok": True, "status_code": 200, "tested_mountpoint": station["mountpoint"]}
        except Exception as e:
            last_status = str(e)
    return {
        "ok": False,
        "status_code": last_status,
        "error": f"Keine der ersten {min(10, len(stations))} Stationen funktionierte mit diesen Zugangsdaten "
                 f"(letzte Antwort: {last_status}). Bei offenen Netzwerken sind Stationen oft einzeln geschuetzt -- "
                 f"am besten direkt die gewuenschte Station hinzufuegen und testen.",
    }


@app.post("/api/failover-test-credentials")
def test_failover_credentials(x_admin_token: str | None = Header(default=None)):
    """Testet die aktuell eingetragenen Caster-Zugangsdaten (Host/User/Pass)."""
    check_token(x_admin_token)
    settings = get_failover_settings()
    return test_caster_credentials(
        settings["eurefip_host"], settings["eurefip_port"],
        settings["eurefip_user"], settings["eurefip_pass"],
    )


def upsert_caster(conn, host: str, port: int, user: str, password: str):
    conn.execute(
        "INSERT INTO casters (host, port, user, pass) VALUES (?,?,?,?) "
        "ON CONFLICT(host) DO UPDATE SET port=excluded.port, user=excluded.user, pass=excluded.pass",
        (host, port, user or "", password or ""),
    )


@app.get("/api/casters")
def list_casters(x_admin_token: str | None = Header(default=None)):
    """Alle gespeicherten Caster (auch ohne Station) mit den Stationen, die sie nutzen -- damit
    man Zugangsdaten EINMAL pro Caster aendern kann, statt pro einzelner Station."""
    check_token(x_admin_token)
    conn = db()
    try:
        rows = conn.execute("SELECT host, port, user, pass FROM casters ORDER BY host").fetchall()
    finally:
        conn.close()
    casters = {r["host"]: {"host": r["host"], "port": r["port"], "user": r["user"], "pass": r["pass"],
                           "station_count": 0, "stations": []} for r in rows}
    for s in get_all_regional_stations():
        host = s.get("caster_host")
        if not host:
            continue
        c = casters.setdefault(host, {"host": host, "port": s.get("caster_port"), "user": s.get("caster_user") or "",
                                      "pass": s.get("caster_pass") or "", "station_count": 0, "stations": []})
        c["station_count"] += 1
        c["stations"].append(s["key"])
    return list(casters.values())


class CasterCredentials(BaseModel):
    port: int
    user: str = ""
    password: str = ""

    @field_validator("port")
    @classmethod
    def _v_port(cls, v):
        return _check_port(v)

    @field_validator("user")
    @classmethod
    def _v_user(cls, v):
        return _check_conf_user(v)

    @field_validator("password")
    @classmethod
    def _v_pass(cls, v):
        return _check_conf_pass(v)


@app.post("/api/casters/{host}/credentials")
def update_caster_credentials(host: str, body: CasterCredentials, x_admin_token: str | None = Header(default=None)):
    """Aendert Port/User/Passwort fuer ALLE Stationen, die diesen Caster-Host
    nutzen, auf einmal -- so muss man bei falsch eingegebenen Zugangsdaten
    nicht jede einzelne Station manuell korrigieren."""
    check_token(x_admin_token)
    conn = db()
    try:
        n = conn.execute(
            "UPDATE regional_stations SET caster_port=?, caster_user=?, caster_pass=? WHERE caster_host=?",
            (body.port, body.user, body.password, host),
        ).rowcount
        upsert_caster(conn, host, body.port, body.user, body.password)
        conn.commit()
    finally:
        conn.close()
    status = write_relay_config() if n else None     # Resync nur noetig, wenn Stationen betroffen sind
    return {"ok": True, "resync_status": status}


class CasterIn(CasterCredentials):
    host: str

    @field_validator("host")
    @classmethod
    def _v_host(cls, v):
        return _check_host(v)


@app.post("/api/casters")
def save_caster(body: CasterIn, x_admin_token: str | None = Header(default=None)):
    """Legt einen Caster mit Zugangsdaten an bzw. aktualisiert ihn (auch ohne Mountpoint/Station)."""
    check_token(x_admin_token)
    return update_caster_credentials(body.host, body, x_admin_token)


@app.delete("/api/casters/{host}")
def delete_caster(host: str, x_admin_token: str | None = Header(default=None)):
    """Entfernt einen Caster aus dem Verzeichnis -- nur, wenn keine Station ihn mehr nutzt."""
    check_token(x_admin_token)
    conn = db()
    try:
        used = conn.execute("SELECT COUNT(*) FROM regional_stations WHERE caster_host=?", (host,)).fetchone()[0]
        if used:
            raise HTTPException(status_code=409, detail=f"{used} Station(en) nutzen diesen Caster noch -- erst entfernen")
        conn.execute("DELETE FROM casters WHERE host=?", (host,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.post("/api/casters/test")
def test_caster_credentials_api(body: CasterCredentials, host: str = "", x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return test_caster_credentials(host, body.port, body.user, body.password)


@app.get("/api/regional-stations")
def list_regional_stations(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return get_all_regional_stations()


class RegionalStationUpdate(BaseModel):
    enabled: bool | None = None
    backup_for: str | None = None     # lokaler Mountpoint, den diese Station ersetzt; "" = keins


@app.post("/api/regional-stations/{key}")
def update_regional_station(key: str, body: RegionalStationUpdate, x_admin_token: str | None = Header(default=None)):
    """Aendert, ob eine Station als eigener Mountpoint aktiv ist und/oder als
    Backup fuer eine andere Quelle (Trimble = RTCM32 oder eine andere Station)
    dient. Schreibt danach sofort die Relay-Config neu + loest Resync aus."""
    check_token(x_admin_token)
    conn = db()
    if not conn.execute("SELECT 1 FROM regional_stations WHERE key=?", (key,)).fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Station nicht gefunden")

    backup_for = body.backup_for

    if body.enabled is not None:
        conn.execute("UPDATE regional_stations SET enabled=? WHERE key=?", (1 if body.enabled else 0, key))
    if backup_for is not None:
        backup_for = backup_for.strip()
        if backup_for:
            if backup_for == key:
                conn.close()
                raise HTTPException(status_code=400, detail="Eine Station kann nicht ihr eigenes Backup sein")
            if backup_for != "RTCM32" and not conn.execute(
                    "SELECT 1 FROM regional_stations WHERE key=?", (backup_for,)).fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="Unbekannter Mountpoint fuer Backup")
            # Backup-Stationen muessen laufen
            conn.execute("UPDATE regional_stations SET backup_for=?, enabled=1 WHERE key=?", (backup_for, key))
        else:
            conn.execute("UPDATE regional_stations SET backup_for=NULL WHERE key=?", (key,))
    conn.commit()
    conn.close()
    status = write_relay_config()
    return {"ok": True, "resync_status": status}


@app.get("/api/euref-sourcetable")
def get_euref_sourcetable_api(search: str = "", host: str | None = None, port: int | None = None,
                              x_admin_token: str | None = Header(default=None)):
    """Live-Sourcetable des Casters (Host/Port aus der Anfrage, sonst die gespeicherten
    Einstellungen), gemischt mit dem lokalen Status (bereits hinzugefuegt/aktiv/Backup)."""
    check_token(x_admin_token)
    try:
        if host:
            _check_host(host)
        if port is not None:
            _check_port(port)
        stations = fetch_euref_sourcetable(host, port)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        return {"error": f"Caster nicht erreichbar: {e}", "stations": [], "total": 0}

    settings = get_failover_settings()
    src_host = host or settings["eurefip_host"]
    all_local = get_all_regional_stations()
    local = {s["key"]: s for s in all_local}
    by_remote = {(s.get("caster_host"), s["remote_mountpoint"]): s for s in all_local}
    if search:
        search_lower = search.lower()
        stations = [
            s for s in stations
            if search_lower in s["mountpoint"].lower()
            or search_lower in s["identifier"].lower()
            or search_lower in s["country"].lower()
        ]

    for s in stations:
        local_entry = by_remote.get((src_host, s["mountpoint"])) or local.get(s["mountpoint"])
        s["added"] = local_entry is not None
        s["enabled"] = bool(local_entry["enabled"]) if local_entry else False

    return {"stations": stations, "total": len(stations)}


class RegionalStationAdd(BaseModel):
    mountpoint: str
    identifier: str
    lat: float
    lon: float
    enabled: bool = True
    backup_for: str | None = None
    caster_host: str | None = None
    caster_port: int | None = None
    caster_user: str | None = None
    caster_pass: str | None = None

    @field_validator("mountpoint")
    @classmethod
    def _v_mp(cls, v):
        return _check_key(v)

    @field_validator("identifier")
    @classmethod
    def _v_ident(cls, v):
        v = re.sub(r"[\x00-\x1f\x7f<>\"']", "", v).strip()
        return v[:80] or "Station"

    @field_validator("caster_host")
    @classmethod
    def _v_host(cls, v):
        return _check_host(v) if v else v

    @field_validator("caster_port")
    @classmethod
    def _v_port(cls, v):
        return _check_port(v) if v is not None else v

    @field_validator("caster_user")
    @classmethod
    def _v_user(cls, v):
        return _check_conf_user(v) if v else v

    @field_validator("caster_pass")
    @classmethod
    def _v_pass(cls, v):
        return _check_conf_pass(v) if v else v


@app.post("/api/regional-stations-add")
def add_regional_station(body: RegionalStationAdd, x_admin_token: str | None = Header(default=None)):
    """Fuegt eine beliebige Station aus einer Live-Sourcetable als neue,
    eigene Regional-Station hinzu (Key = Mountpointname des Quell-Casters,
    z.B. PTBB00DEU0 -> lokaler Mountpoint /PTBB00DEU0). Die Caster-Adresse +
    Zugangsdaten werden PRO STATION gespeichert (Snapshot der aktuellen
    Such-Einstellungen zum Zeitpunkt des Hinzufuegens) -- so koennen
    Stationen von unterschiedlichen Castern (EUREF-IP, RTK2go, ...)
    gleichzeitig und unabhaengig voneinander genutzt werden."""
    check_token(x_admin_token)
    settings = get_failover_settings()
    caster_host = body.caster_host or settings["eurefip_host"]
    caster_port = body.caster_port or settings["eurefip_port"]
    caster_user = body.caster_user if body.caster_user is not None else settings["eurefip_user"]
    caster_pass = body.caster_pass if body.caster_pass is not None else settings["eurefip_pass"]

    backup_for = body.backup_for or None
    if backup_for == body.mountpoint:
        backup_for = None
    conn = db()
    conn.execute(
        """
        INSERT INTO regional_stations (key, name, remote_mountpoint, lat, lon, enabled, backup_for, caster_host, caster_port, caster_user, caster_pass)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(key) DO UPDATE SET
            name=excluded.name, remote_mountpoint=excluded.remote_mountpoint,
            lat=excluded.lat, lon=excluded.lon,
            caster_host=excluded.caster_host, caster_port=excluded.caster_port,
            caster_user=excluded.caster_user, caster_pass=excluded.caster_pass
        """,
        (body.mountpoint, body.identifier, body.mountpoint, body.lat, body.lon,
         1 if (body.enabled or backup_for) else 0, backup_for,
         caster_host, caster_port, caster_user, caster_pass),
    )
    if caster_host:
        upsert_caster(conn, caster_host, caster_port or 2101, caster_user, caster_pass)
    conn.commit()
    conn.close()
    status = write_relay_config()
    return {"ok": True, "resync_status": status}


@app.delete("/api/regional-stations/{key}")
def delete_regional_station(key: str, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    conn.execute("DELETE FROM regional_stations WHERE key=?", (key,))
    conn.execute("UPDATE regional_stations SET backup_for=NULL WHERE backup_for=?", (key,))
    conn.commit()
    conn.close()
    status = write_relay_config()
    return {"ok": True, "resync_status": status}


class RegionalStationRename(BaseModel):
    new_key: str


@app.post("/api/regional-stations-rename/{key}")
def rename_regional_station(key: str, body: RegionalStationRename, x_admin_token: str | None = Header(default=None)):
    """Benennt den LOKALEN Mountpoint-Namen einer Station um (z.B. von
    'PTBB00DEU0' zu 'BRAUNSCHWEIG'). Der Remote-Mountpoint (auf dem
    Quell-Caster) bleibt unveraendert."""
    check_token(x_admin_token)
    new_key = body.new_key.strip().upper().replace(" ", "_")
    if not KEY_RE.match(new_key):
        raise HTTPException(status_code=400, detail="Name: 1-40 Zeichen aus A-Z 0-9 . _ -")
    conn = db()
    existing = conn.execute("SELECT key FROM regional_stations WHERE key=?", (new_key,)).fetchone()
    if existing and new_key != key:
        conn.close()
        raise HTTPException(status_code=409, detail="Name bereits vergeben")
    conn.execute("UPDATE regional_stations SET key=? WHERE key=?", (new_key, key))
    conn.execute("UPDATE regional_stations SET backup_for=? WHERE backup_for=?", (new_key, key))
    conn.commit()
    conn.close()
    status = write_relay_config()
    return {"ok": True, "resync_status": status, "new_key": new_key}


@app.post("/api/failover-manual-switch")
def manual_failover_switch(use_backup: bool, x_admin_token: str | None = Header(default=None)):
    """Schaltet die Trimble (/RTCM32) manuell auf ihr Backup bzw. zurueck. Wirkt ohne
    Caster-Neustart: der Proxy routet neue Verbindungen um und holt laufende
    Rover per Reconnect auf die gewuenschte Quelle."""
    check_token(x_admin_token)
    forced = set(get_forced_primaries())
    if use_backup:
        if "/RTCM32" not in get_failover_map():
            raise HTTPException(status_code=400, detail="Fuer die Trimble ist keine Backup-Station konfiguriert")
        forced.add("/RTCM32")
    else:
        forced.discard("/RTCM32")
    set_setting("failover_forced", ",".join(sorted(forced)))
    create_system_alert("SYSTEM", f"Manuell umgeschaltet auf {'Backup' if use_backup else 'Primaerquelle'}")
    return {"ok": True}


@app.get("/internal/live-mountpoints", dependencies=[Depends(require_local)])
def internal_live_mountpoints():
    """Fuer den gga-proxy: Mountpoints mit aktuell verbundener Quelle (laut Caster-Admin;
    unabhaengig davon, ob sie in sourcetable.dat eingetragen sind)."""
    live = get_live_mountpoints()
    return {"live": sorted(live) if live is not None else None}


@app.get("/internal/failover-map", dependencies=[Depends(require_local)])
def internal_failover_map():
    """Fuer den gga-proxy: Primaer -> Backup-Zuordnung + manuell abgeschaltete Primaerquellen."""
    return {"map": get_failover_map(), "forced": get_forced_primaries(),
            "hidden": ["/" + k for k in sorted(get_pure_backups())]}


# --- Verbindungsdaten / Ping ------------------------------------------------

TRIMBLE_HOST_FALLBACK = os.environ.get("TRIMBLE_HOST", "192.168.0.10")
TRIMBLE_PORTS_FALLBACK = os.environ.get("TRIMBLE_PORTS", "28001,28002")


def get_trimble_settings():
    """Basisstation-Adresse (Host + beide Ausgabe-Ports). In der DB
    gespeichert, damit sie ueber die Web-Oberflaeche aenderbar ist -- so
    kann z.B. ein anderer Betrieb seine eigene Trimble/GNSS-Basis einbinden,
    ohne Umgebungsvariablen/Image anfassen zu muessen."""
    host = get_setting("trimble_host") or TRIMBLE_HOST_FALLBACK
    port_legacy = int(get_setting("trimble_port_legacy") or TRIMBLE_PORTS_FALLBACK.split(",")[0])
    port_msm = int(get_setting("trimble_port_msm") or TRIMBLE_PORTS_FALLBACK.split(",")[-1])
    return {"host": host, "port_legacy": port_legacy, "port_msm": port_msm}


_dns_cache: dict = {}


def resolve_cached(host: str, ttl: float = 60.0):
    """DNS-Aufloesung mit Cache (die GUI fragt alle 15 s; DDNS-Namen aendern sich selten)."""
    now = time.monotonic()
    hit = _dns_cache.get(host)
    if hit and now - hit[0] < ttl:
        return hit[1]
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = None
    _dns_cache[host] = (now, ip)
    return ip


@app.get("/api/connection-info")
def connection_info(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    public_ip = resolve_cached(get_sys("public_hostname"))
    trimble = get_trimble_settings()
    live = get_live_mountpoints()
    fmap = get_failover_map()
    forced = set(get_forced_primaries())
    pure = get_pure_backups()

    def entry(key, label):
        mp = "/" + key
        is_live = None if live is None else (mp in live)
        serving = mp if is_live else None
        backups = fmap.get(mp, [])
        if backups and live is not None and (not is_live or mp in forced):
            live_b = [b for b in backups if b in live]
            serving = live_b[0] if live_b else None
        return {"name": key, "label": label, "live": is_live,
                "serving": serving[1:] if serving else None,
                "backups": [b[1:] for b in backups]}

    details = ([entry("RTCM", "Trimble, Legacy (RTCM 3.1)")] if get_sys("trimble_legacy") else []) \
        + [entry("RTCM32", "Trimble, MSM (RTCM 3.2)")]
    for s in get_all_regional_stations():
        if s["enabled"] and s["key"] not in pure:
            details.append(entry(s["key"], s["name"]))
    details.append({"name": "NEAR", "label": "automatische Stationswahl nach GGA-Position (nur RTCM 3.2+)",
                    "live": None, "serving": None, "backups": []})
    mountpoints = [d["name"] for d in details]

    return {
        "server_hostname": get_sys("public_hostname"),
        "server_ip": public_ip,
        "port": get_sys("public_ntrip_port"),
        "mountpoints": mountpoints,
        "mountpoint_details": details,
        "trimble_host": trimble["host"],
        "trimble_relay": {d["name"]: d["live"] for d in details if d["name"] in ("RTCM", "RTCM32")},
    }


class TrimbleSettings(BaseModel):
    host: str
    port_legacy: int
    port_msm: int

    @field_validator("host")
    @classmethod
    def _v_host(cls, v):
        return _check_host(v)

    @field_validator("port_legacy", "port_msm")
    @classmethod
    def _v_port(cls, v):
        return _check_port(v)


@app.get("/api/trimble-settings")
def get_trimble_settings_api(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return get_trimble_settings()


@app.post("/api/trimble-settings")
def update_trimble_settings(body: TrimbleSettings, x_admin_token: str | None = Header(default=None)):
    """Aendert die Adresse der Basisstation (Trimble/GNSS-Empfaenger) und
    schreibt sofort die 'relay pull'-Zeilen in ntripcaster.conf neu +
    loest einen resync aus, damit die Aenderung sofort wirkt. So kann z.B.
    ein anderer Betrieb seine eigene Basis einbinden, ohne das Image/die
    Umgebungsvariablen anfassen zu muessen."""
    check_token(x_admin_token)
    set_setting("trimble_host", body.host)
    set_setting("trimble_port_legacy", str(body.port_legacy))
    set_setting("trimble_port_msm", str(body.port_msm))
    status = write_relay_config()
    return {"ok": True, "resync_status": status}


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


class ConnectEvent(BaseModel):
    username: str
    session_id: str
    ip: str | None = None
    mountpoint: str | None = None
    requested_mountpoint: str | None = None


class DisconnectEvent(BaseModel):
    username: str
    session_id: str


class HeartbeatEvent(BaseModel):
    username: str
    session_id: str


@app.post("/internal/heartbeat", dependencies=[Depends(require_local)])
def heartbeat_event(ev: HeartbeatEvent):
    """Lebenszeichen vom gga-proxy, solange RTCM-Daten zum Rover fliessen --
    unabhaengig davon, ob der Rover GGA sendet (haelt den Online-Status
    korrekt, auch fuer Rover ohne Positionsrueckmeldung)."""
    now = utcnow().isoformat()
    conn = db()
    conn.execute(
        "UPDATE machine_status SET online=1, last_seen=? WHERE username=?",
        (now, ev.username),
    )
    conn.execute("UPDATE sessions SET last_seen=? WHERE session_id=?", (now, ev.session_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/internal/sessions-reset", dependencies=[Depends(require_local)])
def sessions_reset():
    """Der gga-proxy ruft das beim Start auf: alle bisher offenen Sessions gehoeren zu
    einem beendeten Prozess und werden geschlossen (sonst falsche Mehrfachnutzungs-Alarme)."""
    now = utcnow().isoformat()
    conn = db()
    n = conn.execute("UPDATE sessions SET ended_at=? WHERE ended_at IS NULL", (now,)).rowcount
    conn.execute("UPDATE machine_status SET online=0 WHERE online=1")
    conn.commit()
    conn.close()
    return {"ok": True, "closed": n}


SESSION_STALE_SECONDS = 120


def close_stale_sessions(conn):
    """Sessions ohne Lebenszeichen (Heartbeat alle ~10 s) seit > 2 Minuten gelten als beendet."""
    cutoff = (utcnow() - timedelta(seconds=SESSION_STALE_SECONDS)).isoformat()
    conn.execute(
        "UPDATE sessions SET ended_at=? WHERE ended_at IS NULL AND COALESCE(last_seen, started_at) < ?",
        (utcnow().isoformat(), cutoff),
    )
    conn.commit()


class GgaEvent(BaseModel):
    username: str
    session_id: str
    lat: float
    lon: float
    fix_quality: int
    sat_count: int


@app.post("/internal/connect-event", dependencies=[Depends(require_local)])
def connect_event(ev: ConnectEvent):
    now = utcnow().isoformat()
    conn = db()
    # Verwaiste alte Sessions DERSELBEN IP automatisch schliessen (eindeutig
    # dasselbe Geraet, das neu verbunden hat -- z.B. nach einem Container-
    # Neustart, bei dem das Disconnect-Event nie gefeuert wurde). Nur
    # Sessions einer ANDEREN IP bleiben offen und zaehlen als echter
    # Ueberlappungs-Kandidat fuer den Mehrfachnutzungs-Alarm.
    conn.execute(
        "UPDATE sessions SET ended_at=? WHERE username=? AND ip=? AND ended_at IS NULL AND session_id!=?",
        (now, ev.username, ev.ip, ev.session_id),
    )
    conn.execute(
        "INSERT OR REPLACE INTO sessions (session_id, username, ip, mountpoint, started_at, ended_at, last_seen) VALUES (?,?,?,?,?,NULL,?)",
        (ev.session_id, ev.username, ev.ip, ev.mountpoint, now, now),
    )
    conn.execute(
        """
        INSERT INTO machine_status (username, online, online_since, last_seen, last_ip, last_mountpoint, last_requested_mountpoint)
        VALUES (?, 1, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            online=1, online_since=excluded.online_since, last_seen=excluded.last_seen,
            last_ip=excluded.last_ip, last_mountpoint=excluded.last_mountpoint,
            last_requested_mountpoint=excluded.last_requested_mountpoint
        """,
        (ev.username, now, now, ev.ip, ev.mountpoint, ev.requested_mountpoint or ev.mountpoint),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/internal/disconnect-event", dependencies=[Depends(require_local)])
def disconnect_event(ev: DisconnectEvent):
    now = utcnow().isoformat()
    conn = db()
    conn.execute(
        "UPDATE sessions SET ended_at=? WHERE session_id=? AND ended_at IS NULL",
        (now, ev.session_id),
    )
    # Nur als "offline" markieren, wenn KEINE andere Session dieses Users mehr aktiv ist
    still_active = conn.execute(
        "SELECT COUNT(*) AS c FROM sessions WHERE username=? AND ended_at IS NULL",
        (ev.username,),
    ).fetchone()["c"]
    if still_active == 0:
        conn.execute(
            "UPDATE machine_status SET online=0, last_seen=? WHERE username=?",
            (now, ev.username),
        )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/internal/gga-event", dependencies=[Depends(require_local)])
def gga_event(ev: GgaEvent):
    now = utcnow().isoformat()
    base_lat, base_lon = get_base_position()
    distance_km = round(haversine_km(base_lat, base_lon, ev.lat, ev.lon), 2)
    conn = db()
    conn.execute(
        """
        INSERT INTO machine_status (username, online, last_seen, last_lat, last_lon,
            last_fix_quality, last_sat_count, last_distance_km, last_pos_at)
        VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            online=1, last_seen=excluded.last_seen, last_lat=excluded.last_lat,
            last_lon=excluded.last_lon, last_fix_quality=excluded.last_fix_quality,
            last_sat_count=excluded.last_sat_count, last_distance_km=excluded.last_distance_km,
            last_pos_at=excluded.last_pos_at
        """,
        (ev.username, now, ev.lat, ev.lon, ev.fix_quality, ev.sat_count, distance_km, now),
    )
    conn.execute(
        "INSERT INTO position_history (username, session_id, lat, lon, fix_quality, sat_count) VALUES (?,?,?,?,?,?)",
        (ev.username, ev.session_id, ev.lat, ev.lon, ev.fix_quality, ev.sat_count),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


FIX_QUALITY_LABELS = {
    0: "Kein Fix", 1: "GPS", 2: "DGPS", 3: "PPS",
    4: "RTK-Fix", 5: "RTK-Float", 6: "Schaetzung",
}


@app.get("/api/position-history")
def position_history(
    username: str | None = None,
    hours: int = 24,
    date: str | None = None,
    since: str | None = None,
    limit: int = 50000,
    x_admin_token: str | None = Header(default=None),
):
    """Positionsverlauf (Track) fuer einen oder alle User: ab `since` (UTC, YYYY-MM-DD HH:MM:SS),
    fuer ein Kalendertag (`date`=YYYY-MM-DD) oder die letzten `hours` Stunden. Alles als
    Bereichsabfrage auf dem Zeit-Index; Ergebnis auf `limit` Zeilen begrenzt."""
    check_token(x_admin_token)
    conditions, params = [], []
    if username:
        conditions.append("username=?")
        params.append(username)
    try:
        if since:
            datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
            conditions.append("ts >= ?")
            params.append(since)
        elif date:
            day = datetime.strptime(date, "%Y-%m-%d")
            conditions.append("ts >= ? AND ts < ?")
            params += [day.strftime("%Y-%m-%d 00:00:00"), (day + timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")]
        else:
            conditions.append("ts >= ?")
            params.append((utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S"))
    except ValueError:
        raise HTTPException(status_code=422, detail="Ungueltiges Datum/Zeitformat")
    limit = max(1, min(limit, 200000))
    conn = db()
    try:
        rows = conn.execute(
            f"SELECT username, ts, lat, lon, fix_quality, sat_count FROM position_history "
            f"WHERE {' AND '.join(conditions)} ORDER BY ts ASC LIMIT ?",
            (*params, limit),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@app.get("/api/alerts")
def list_alerts(
    include_resolved: bool = True,
    include_system: bool = True,
    x_admin_token: str | None = Header(default=None),
):
    check_token(x_admin_token)
    conn = db()
    conditions = []
    if not include_resolved:
        conditions.append("resolved_at IS NULL")
    if not include_system:
        conditions.append("username != 'SYSTEM'")
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = conn.execute(f"SELECT * FROM alerts {where} ORDER BY detected_at DESC LIMIT 200").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    conn.execute("UPDATE alerts SET resolved_at=? WHERE id=?", (utcnow().isoformat(), alert_id))
    conn.commit()
    conn.close()
    return {"ok": True}


class AlertSettings(BaseModel):
    grace_seconds: int | None = None
    distance_m: float | None = None
    auto_kick: bool | None = None
    webhook_url: str | None = None


@app.get("/api/alert-settings")
def get_alert_settings(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    return {
        "grace_seconds": int(float(get_setting("alert_grace_seconds") or 60)),
        "distance_m": float(get_setting("alert_distance_m") or 300),
        "auto_kick": (get_setting("alert_auto_kick") or "false").lower() == "true",
        "webhook_url": get_setting("alert_webhook_url") or "",
    }


@app.post("/api/alert-settings")
def update_alert_settings(body: AlertSettings, x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    if body.grace_seconds is not None:
        set_setting("alert_grace_seconds", str(body.grace_seconds))
    if body.distance_m is not None:
        set_setting("alert_distance_m", str(body.distance_m))
    if body.auto_kick is not None:
        set_setting("alert_auto_kick", "true" if body.auto_kick else "false")
    if body.webhook_url is not None:
        set_setting("alert_webhook_url", body.webhook_url)
    return {"ok": True}


@app.get("/api/machine-status")
def machine_status(x_admin_token: str | None = Header(default=None)):
    check_token(x_admin_token)
    conn = db()
    # Online-Timeout: wenn > 60s kein Lebenszeichen, als offline behandeln
    rows = conn.execute(
        "SELECT ms.* FROM machine_status ms JOIN users u ON u.username = ms.username ORDER BY ms.username"
    ).fetchall()
    conn.close()
    result = []
    now = utcnow()
    for r in rows:
        d = dict(r)
        if d["online"] and d["last_seen"]:
            try:
                last = datetime.fromisoformat(d["last_seen"])
                if (now - last).total_seconds() > 60:
                    d["online"] = 0
            except Exception:
                pass
        d["fix_quality_label"] = FIX_QUALITY_LABELS.get(d["last_fix_quality"], "-")
        result.append(d)
    return result


@app.get("/api/stations")
def stations(x_admin_token: str | None = Header(default=None)):
    """Fragt den Caster nach aktuell verbundenen Quellen (Trimble-Relays +
    Regional-Backups). Zeigt auch konfigurierte, aber (noch) nicht
    verbundene Mountpoints als 'nicht verbunden' an (z.B. BS/MUC, solange
    der BKG-Account nicht freigeschaltet ist)."""
    check_token(x_admin_token)
    try:
        r = requests.get(
            f"{CASTER_URL}/admin",
            params={"mode": "sources", "nohtml": "1"},
            auth=(CASTER_ADMIN_USER, get_setting("caster_admin_pass")),
            timeout=5,
        )
        text = r.text
    except Exception as e:
        return {"error": str(e), "sources": []}

    sources = []
    seen_mountpoints = set()
    for line in text.splitlines():
        if "[Mountpoint:" not in line:
            continue
        def grab(key):
            m = re.search(rf"\[{key}: ([^\]]*)\]", line)
            return m.group(1) if m else None
        mp = grab("Mountpoint")
        seen_mountpoints.add(mp)
        sources.append({
            "mountpoint": mp,
            "ip": grab("IP"),
            "clients": grab("Clients"),
            "connected_for": grab("Connected for"),
            "kbytes_read": grab("KBytes read"),
            "online": True,
        })

    # Konfigurierte, aber nicht (mehr) verbundene Mountpoints ergaenzen
    # (NEAR ist virtuell, hat keine eigene physische Quelle -> ausgenommen)
    expected = ["/RTCM", "/RTCM32"] + [s["mountpoint"] for s in get_regional_stations()]
    for mp in expected:
        if mp not in seen_mountpoints:
            sources.append({
                "mountpoint": mp, "ip": None, "clients": None,
                "connected_for": None, "kbytes_read": None, "online": False,
            })

    return {"sources": sources}


# --- Web-UI (S4) -----------------------------------------------------------
app.mount("/ui", StaticFiles(directory="/app/static", html=True), name="ui")


@app.get("/")
def root():
    return FileResponse("/app/static/index.html")
