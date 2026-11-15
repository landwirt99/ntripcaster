# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 landwirt99
"""
GGA-Collector-Proxy (S5)

Sitzt transparent zwischen Rovern und dem NtripCaster (BKG Caster 2.0.x, der
selbst keine Koordinaten loggt). Der Proxy veraendert das NTRIP-Protokoll NICHT:

  * Request, Antwort-Header (HTTP/1.1 200 OK, Ntrip-Version, chunked, ...)
    und Datenstrom gehen 1:1 zwischen Rover und Caster durch.
  * Mitgelesen wird nur:
      - Rover -> Caster: NMEA-GGA-Saetze (Position/Satelliten/Fix) -> Backend
      - Caster -> Rover: RTCM 1005/1006 (Basiskoordinate) -> Backend
      - Connect/Disconnect/Heartbeat (Username aus dem Basic-Auth-Header)

Zusaetzlich (Failover): Hat eine Quelle ein Backup konfiguriert (Zuordnung vom
Backend), routet der Proxy neue Verbindungen auf das Backup, solange die
Primaerquelle ausgefallen ist, und holt die Rover per Reconnect zurueck, sobald
sie wieder stabil laeuft. Backup-Stationen tauchen nicht in der Sourcetable auf.

Schutz des oeffentlichen Ports: nur GET auf "/" (Sourcetable) und einfache
Mountpoint-Namen, /admin und /oper werden nie durchgereicht, Zeitlimit fuer den
Request-Kopf, Verbindungslimits, GGA nur von authentifizierten Sessions.

Einzige Ausnahme ist der virtuelle Mountpoint /NEAR: Der Proxy verbindet
zunaechst mit /RTCM32, wartet auf die erste GGA-Position des Rovers und
schaltet dann -- falls eine naehere Station existiert -- einmalig auf diese
um. Nur fuer /NEAR werden Antwort-Header und Chunk-Rahmen vom Proxy selbst
erzeugt, damit der Rover beim Umschalten einen durchgehenden Strom sieht.
Da der Caster /NEAR nicht kennt, haengt der Proxy bei Sourcetable-Anfragen als
einzige Aenderung die STR-Zeile fuer /NEAR (mit NMEA-Flag 1) an. Die
Sourcetable wird im NTRIP-1-Format des Casters geholt, weil die App 20260514
nur dieses akzeptiert; ueber die GUI-Systemeinstellungen laesst sich das auf die
unveraenderte NTRIP-2.0-Antwort umstellen.
"""

import asyncio
import base64
import logging
import math
import os
import re
import uuid

import httpx

# Schutz des (oeffentlich erreichbaren) Ports
HEAD_TIMEOUT = 10.0          # s fuer den kompletten Request-Kopf
MAX_CONNECTIONS = 300
MAX_CONNECTIONS_PER_IP = 20
MOUNTPOINT_RE = re.compile(r"^/[A-Za-z0-9._-]{1,40}$")
BLOCKED_PATHS = ("/admin", "/oper")     # Admin-Bereich des Casters nie nach aussen durchreichen

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "5000"))
CASTER_HOST = os.environ.get("CASTER_HOST", "caster")
CASTER_PORT = int(os.environ.get("CASTER_PORT", "5000"))
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gga-proxy")

http_client = httpx.AsyncClient(timeout=3.0)


def nmea_to_decimal(value: str, hemisphere: str) -> float | None:
    """Wandelt NMEA ddmm.mmmm (oder dddmm.mmmm fuer Longitude) in Dezimalgrad um."""
    if not value:
        return None
    try:
        dot = value.index(".")
        deg_len = dot - 2
        degrees = float(value[:deg_len])
        minutes = float(value[deg_len:])
        dec = degrees + minutes / 60.0
        if hemisphere in ("S", "W"):
            dec = -dec
        return dec
    except Exception:
        return None


GGA_RE = re.compile(rb"\$(?:GP|GN|GL)GGA,[^\r\n]*")

NEAREST_MOUNTPOINT_NAME = "/NEAR"
NEAREST_DEFAULT_TARGET = "/RTCM32"
# /NEAR prueft regelmaessig anhand der GGA-Position, ob eine bessere Station existiert:
# (Werte werden regelmaessig aus den GUI-Systemeinstellungen geladen, siehe load_proxy_settings)
NEAR_RECHECK_S = 30.0        # Abstand zwischen zwei Pruefungen
NEAR_MIN_DWELL_S = 120.0     # Mindestverweildauer auf einer Station
NEAR_HYSTERESIS_KM = 10.0    # neue Station muss so viel naeher sein
SOURCETABLE_MODE = "v1"
# Nur diese Mountpoints liefern die Koordinate der eigenen Basis (Trimble); die
# 1005/1006-Positionen anderer Quellen (BARUM, EUREF ...) duerfen sie nicht ueberschreiben.
OWN_BASE_MOUNTPOINTS = ("/RTCM", "/RTCM32")
BASE_POS_INTERVAL_S = 30.0
_BASE_POS_LAST = -1e9
STATION_COORDS = {
    "/RTCM32": (52.52, 13.40),  # Fallback, bis das Backend erreichbar ist
}


async def load_station_coords():
    """Holt die /NEAR-Kandidatenliste vom Backend."""
    global STATION_COORDS
    try:
        r = await http_client.get(f"{BACKEND_URL}/internal/near-candidates", timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            STATION_COORDS = {mp: tuple(coords) for mp, coords in data.items()}
            log.info("Near-Kandidaten geladen: %s", list(STATION_COORDS.keys()))
    except Exception as e:
        log.warning("Konnte Near-Kandidaten nicht laden: %s", e)


FAILOVER = {"map": {}, "forced": set(), "hidden": set()}
FAILBACK_STABLE_S = 30.0       # Primaerquelle muss so lange stabil live sein, bevor Rover zurueckgeholt werden (GUI-Einstellung)
FAILOVER_WATCH_S = 5.0
PRIMARY_UP_SINCE: dict = {}


async def load_proxy_settings():
    """Systemeinstellungen aus der GUI (NEAR-Parameter, Failback-Zeit, Sourcetable-Format)."""
    global NEAR_RECHECK_S, NEAR_MIN_DWELL_S, NEAR_HYSTERESIS_KM, FAILBACK_STABLE_S, SOURCETABLE_MODE
    try:
        r = await http_client.get(f"{BACKEND_URL}/internal/proxy-settings", timeout=5.0)
        if r.status_code == 200:
            d = r.json()
            NEAR_RECHECK_S = float(d["near_recheck_s"])
            NEAR_MIN_DWELL_S = float(d["near_min_dwell_s"])
            NEAR_HYSTERESIS_KM = float(d["near_hysteresis_km"])
            FAILBACK_STABLE_S = float(d["failback_stable_s"])
            SOURCETABLE_MODE = d.get("sourcetable_mode", "v1")
    except Exception as e:
        log.warning("Konnte Proxy-Einstellungen nicht laden: %s", e)


async def load_failover_map():
    """Primaer -> Backup-Zuordnung (+ manuell abgeschaltete Primaerquellen) vom Backend."""
    try:
        r = await http_client.get(f"{BACKEND_URL}/internal/failover-map", timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            FAILOVER["map"] = {k: list(v) for k, v in data.get("map", {}).items()}
            FAILOVER["forced"] = set(data.get("forced", []))
            FAILOVER["hidden"] = set(data.get("hidden", []))
    except Exception as e:
        log.warning("Konnte Failover-Zuordnung nicht laden: %s", e)


async def resolve_target(mp: str, current: str | None = None) -> str:
    """Welche Quelle bedient einen Rover, der `mp` angefordert hat?
    Solange die Primaerquelle live ist -> sie selbst (Backups werden ignoriert).
    Ist sie ausgefallen (oder manuell abgeschaltet) -> erstes live-Backup.
    `current` = Quelle, auf der der Rover gerade haengt: nach einem Failover wird er
    erst zurueckgeholt, wenn die Primaerquelle FAILBACK_STABLE_S lang stabil war."""
    backups = FAILOVER["map"].get(mp)
    if not backups:
        return mp
    live = await live_mountpoints()
    if live is None:
        return current or mp
    now = asyncio.get_event_loop().time()
    primary_up = mp in live and mp not in FAILOVER["forced"]
    if primary_up:
        since = PRIMARY_UP_SINCE.setdefault(mp, now)
        if current and current != mp and now - since < FAILBACK_STABLE_S:
            return current
        return mp
    PRIMARY_UP_SINCE.pop(mp, None)
    for b in backups:
        if b in live:
            return b
    return mp


def rewrite_request(head: bytes, requested: str, target: str) -> bytes:
    if requested == target:
        return head
    line, sep, rest = head.partition(b"\r\n")
    return line.replace(requested.encode(), target.encode(), 1) + sep + rest


async def failover_watch(logical: str, actual: str, server_writer, client_writer, session: dict):
    """Holt Rover von einem Backup zurueck bzw. auf ein Backup, wenn sich die
    Lage geaendert hat: beendet die Verbindung, die App verbindet sich neu und
    wird dann auf die richtige Quelle geroutet."""
    try:
        while True:
            await asyncio.sleep(FAILOVER_WATCH_S)
            want = await resolve_target(logical, current=actual)
            if want != actual:
                log.info("Failover-Wechsel: %s -> %s, Rover wird neu verbunden (user=%s)",
                         actual, want, session.get("username"))
                for w in (server_writer, client_writer):
                    try:
                        w.close()
                    except Exception:
                        pass
                return
    except asyncio.CancelledError:
        pass


async def refresh_station_coords():
    while True:
        await load_proxy_settings()
        await load_failover_map()
        await load_station_coords()
        # Solange das Backend noch nicht antwortet (kurz nach Container-Start),
        # schnell erneut versuchen.
        await asyncio.sleep(5 if len(STATION_COORDS) <= 1 else 60)


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


_LIVE_CACHE = {"ts": 0.0, "mps": None}


async def live_mountpoints():
    """Mountpoints, hinter denen der Caster gerade eine Quelle hat (laut Backend/Caster-
    Admin, unabhaengig von sourcetable.dat). Kurz gecacht; None, wenn nicht
    ermittelbar (dann wird nicht gefiltert)."""
    now = asyncio.get_event_loop().time()
    if _LIVE_CACHE["mps"] is not None and now - _LIVE_CACHE["ts"] < 10:
        return _LIVE_CACHE["mps"]
    try:
        r = await http_client.get(f"{BACKEND_URL}/internal/live-mountpoints", timeout=6.0)
        data = r.json().get("live") if r.status_code == 200 else None
        if data is None:
            return None
        mps = set(data)
        _LIVE_CACHE.update(ts=now, mps=mps)
        return mps
    except Exception as e:
        log.warning("Live-Mountpoints nicht ermittelbar: %s", e)
        return None


def pick_nearest_mountpoint(lat: float, lon: float, live=None) -> str:
    """Naechste Station; mit live nur Stationen mit aktuell verbundener Quelle."""
    best_mp, best_dist = NEAREST_DEFAULT_TARGET, float("inf")
    for mp, (slat, slon) in STATION_COORDS.items():
        if live and mp not in live and mp != NEAREST_DEFAULT_TARGET:
            continue
        d = haversine_km(lat, lon, slat, slon)
        if d < best_dist:
            best_dist = d
            best_mp = mp
    return best_mp


# --- RTCM3 Basiskoordinate (Msg 1005/1006) --------------------------------
_WGS84_A = 6378137.0
_WGS84_F = 1 / 298.257223563
_WGS84_B = _WGS84_A * (1 - _WGS84_F)
_WGS84_E2 = 1 - (_WGS84_B ** 2) / (_WGS84_A ** 2)


class BitReader:
    """Liest MSB-first Bitfelder aus RTCM3-Payload-Bytes (big-endian)."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_uint(self, nbits: int) -> int:
        val = 0
        for _ in range(nbits):
            byte_idx = self.pos // 8
            bit_idx = 7 - (self.pos % 8)
            bit = (self.data[byte_idx] >> bit_idx) & 1
            val = (val << 1) | bit
            self.pos += 1
        return val

    def read_int(self, nbits: int) -> int:
        val = self.read_uint(nbits)
        if val >= (1 << (nbits - 1)):
            val -= (1 << nbits)
        return val


def ecef_to_geodetic(x: float, y: float, z: float):
    lon = math.atan2(y, x)
    p = math.sqrt(x * x + y * y)
    lat = math.atan2(z, p * (1 - _WGS84_E2))
    for _ in range(6):
        sinlat = math.sin(lat)
        n = _WGS84_A / math.sqrt(1 - _WGS84_E2 * sinlat * sinlat)
        lat = math.atan2(z + _WGS84_E2 * n * sinlat, p)
    return math.degrees(lat), math.degrees(lon)


def parse_rtcm_1005_1006(payload: bytes):
    """Dekodiert aus einem RTCM3-Payload die Basis-ARP-Koordinate (Msg 1005/1006).
    Gibt (lat, lon) zurueck oder None."""
    if len(payload) < 19:
        return None
    br = BitReader(payload)
    msg_num = br.read_uint(12)
    if msg_num not in (1005, 1006):
        return None
    br.read_uint(12)  # Reference Station ID
    br.read_uint(6)   # ITRF Realization Year
    br.read_uint(1)   # GPS indicator
    br.read_uint(1)   # GLONASS indicator
    br.read_uint(1)   # Galileo indicator
    br.read_uint(1)   # Reference-Station indicator
    ecef_x = br.read_int(38) * 0.0001
    br.read_uint(1)   # Single Receiver Oscillator
    br.read_uint(1)   # Reserved
    ecef_y = br.read_int(38) * 0.0001
    br.read_uint(2)   # Quarter Cycle Indicator
    ecef_z = br.read_int(38) * 0.0001

    r = math.sqrt(ecef_x ** 2 + ecef_y ** 2 + ecef_z ** 2)
    if not (6_300_000 < r < 6_450_000):
        return None

    lat, lon = ecef_to_geodetic(ecef_x, ecef_y, ecef_z)
    return lat, lon


def _make_crc24q_table():
    table = []
    for i in range(256):
        c = i << 16
        for _ in range(8):
            c <<= 1
            if c & 0x1000000:
                c ^= 0x1864CFB
        table.append(c & 0xFFFFFF)
    return table


_CRC24Q_TABLE = _make_crc24q_table()


def crc24q(data: bytes) -> int:
    """CRC-24Q (Qualcomm), wie von RTCM3 fuer die Frame-Pruefsumme verwendet (tabellengesteuert)."""
    crc = 0
    table = _CRC24Q_TABLE
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFF) ^ table[((crc >> 16) ^ byte) & 0xFF]
    return crc


def extract_rtcm_frames(buf: bytearray):
    """Zerlegt den Bytestrom in vollstaendige, CRC-geprueffte RTCM3-Frames
    (Praeambel 0xD3), behaelt unvollstaendige Rest-Bytes im Puffer.

    Ohne CRC-Pruefung wuerde ein zufaelliges 0xD3-Byte mitten in einer anderen
    Nachricht als Frame-Anfang erkannt und die Basiskoordinate waere Muell."""
    frames = []
    while True:
        idx = buf.find(b"\xd3")
        if idx == -1:
            buf.clear()
            break
        if idx > 0:
            del buf[:idx]
        if len(buf) < 3:
            break
        length = ((buf[1] & 0x03) << 8) | buf[2]
        total_len = 3 + length + 3  # Header(3) + Payload + CRC24Q(3)
        if len(buf) < total_len:
            break

        frame_bytes = bytes(buf[:3 + length])
        crc_bytes = buf[3 + length:total_len]
        received_crc = (crc_bytes[0] << 16) | (crc_bytes[1] << 8) | crc_bytes[2]

        if crc24q(frame_bytes) == received_crc:
            frames.append(bytes(buf[3:3 + length]))
            del buf[:total_len]
        else:
            del buf[:1]
    return frames


def parse_gga(line: bytes):
    try:
        text = line.decode("ascii", errors="ignore")
        fields = text.split(",")
        # $GPGGA,time,lat,N/S,lon,E/W,fixq,numsat,hdop,alt,M,...
        if len(fields) < 8:
            return None
        lat = nmea_to_decimal(fields[2], fields[3])
        lon = nmea_to_decimal(fields[4], fields[5])
        fix_quality = int(fields[6]) if fields[6] else 0
        sat_count = int(fields[7]) if fields[7] else 0
        if lat is None or lon is None:
            return None
        return {"lat": lat, "lon": lon, "fix_quality": fix_quality, "sat_count": sat_count}
    except Exception:
        return None


def parse_request_head(head: bytes):
    """Extrahiert Mountpoint + Username (aus Basic-Auth) aus dem Request."""
    try:
        text = head.decode("latin-1", errors="ignore")
        lines = text.split("\r\n")
        mountpoint = None
        username = None
        m = re.match(r"GET (/\S*) HTTP", lines[0])
        if m:
            mountpoint = m.group(1)
        for l in lines[1:]:
            if l.lower().startswith("authorization: basic "):
                b64 = l.split(" ", 2)[2].strip()
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                    username = decoded.split(":", 1)[0]
                except Exception:
                    pass
        return mountpoint, username
    except Exception:
        return None, None


async def notify_backend(path: str, payload: dict):
    try:
        await http_client.post(f"{BACKEND_URL}{path}", json=payload)
    except Exception as e:
        log.warning("Backend-Benachrichtigung fehlgeschlagen (%s): %s", path, e)


class Dechunker:
    """Zerlegt HTTP-Chunked-Daten (nur zum Mitlesen bzw. fuer /NEAR)."""

    def __init__(self):
        self.pending = bytearray()
        self.chunk_left = 0
        self.need_size = True

    def feed(self, data: bytes):
        """Liefert (Nutzbytes, Stream_zu_Ende)."""
        pending = self.pending
        pending.extend(data)
        out = bytearray()
        while True:
            if self.need_size:
                idx = pending.find(b"\r\n")
                if idx < 0:
                    if len(pending) > 64:   # kein gueltiger Chunk-Kopf
                        pending.clear()
                    break
                size_str = bytes(pending[:idx]).split(b";")[0].strip()
                del pending[:idx + 2]
                try:
                    self.chunk_left = int(size_str, 16)
                except ValueError:
                    self.chunk_left = 0
                if self.chunk_left == 0:
                    return bytes(out), True
                self.need_size = False
            if self.chunk_left:
                n = min(self.chunk_left, len(pending))
                if n == 0:
                    break
                out.extend(pending[:n])
                del pending[:n]
                self.chunk_left -= n
            if self.chunk_left == 0:
                if len(pending) < 2:
                    break
                del pending[:2]               # CRLF nach den Chunk-Daten
                self.need_size = True
        return bytes(out), False


_HEAD_PREFIXES = (b"HTTP/", b"ICY", b"SOURCETABLE")


def head_kind(buf: bytes):
    """True: Antwort beginnt mit einer Statuszeile, False: nicht, None: noch unklar."""
    for p in _HEAD_PREFIXES:
        if buf.startswith(p):
            return True
    if any(p.startswith(bytes(buf)) for p in _HEAD_PREFIXES):
        return None
    return False


async def pump_client_to_server(reader, writer, session: dict, switch_target: dict, current_target: str):
    """Rover -> Caster. Reicht Bytes 1:1 durch und liest GGA-Saetze mit.
    Bei /NEAR-Sessions: prueft alle NEAR_RECHECK_S Sekunden anhand der aktuellen
    GGA-Position, ob eine bessere Station existiert -- falls ja, kehrt die
    Funktion zurueck, damit handle_client neu verbindet. Gewechselt wird nur,
    wenn die aktuelle Station nicht mehr live ist oder die neue mindestens
    NEAR_HYSTERESIS_KM naeher liegt (und nach NEAR_MIN_DWELL_S Verweildauer)."""
    buffer = b""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()

            # Saetze koennen ueber TCP-Paketgrenzen verteilt sein.
            buffer += data
            if b"\n" not in buffer and len(buffer) > 4096:
                buffer = buffer[-256:]
            if b"\n" in buffer:
                complete, _, buffer = buffer.rpartition(b"\n")
                buffer = buffer[-256:]
                for match in GGA_RE.finditer(complete):
                    gga = parse_gga(match.group(0))
                    if not gga:
                        continue
                    # Nur fuer Sessions, bei denen der Caster die Anmeldung akzeptiert hat
                    if not session.get("connected"):
                        continue
                    if session.get("username"):
                        log.info("GGA von %s: %.6f, %.6f (fix=%s, %s Sats)",
                                 session["username"], gga["lat"], gga["lon"],
                                 gga["fix_quality"], gga["sat_count"])
                        gga_out = dict(gga)
                        gga_out["username"] = session["username"]
                        gga_out["session_id"] = session["session_id"]
                        asyncio.create_task(notify_backend("/internal/gga-event", gga_out))

                    if session.get("is_nearest"):
                        now = asyncio.get_event_loop().time()
                        first = not session.get("switched")
                        if first or now - session.get("last_near_check", 0.0) >= NEAR_RECHECK_S:
                            session["switched"] = True
                            session["last_near_check"] = now
                            live = await live_mountpoints()
                            best = pick_nearest_mountpoint(gga["lat"], gga["lon"], live)
                            if best != current_target:
                                cur_live = (live is None or current_target == NEAREST_DEFAULT_TARGET
                                            or current_target in live)
                                cur_xy = STATION_COORDS.get(current_target)
                                best_xy = STATION_COORDS.get(best)
                                closer_by = (haversine_km(gga["lat"], gga["lon"], *cur_xy)
                                             - haversine_km(gga["lat"], gga["lon"], *best_xy)) if cur_xy and best_xy else 0.0
                                dwelled = (session.get("last_switch") is None
                                           or now - session["last_switch"] >= NEAR_MIN_DWELL_S)
                                if (not cur_live) or (closer_by >= NEAR_HYSTERESIS_KM and dwelled):
                                    session["last_switch"] = now
                                    log.info("Nearest: %s -> %s (%.1f km naeher, aktuelle Station live=%s, user=%s)",
                                             current_target, best, closer_by, cur_live, session.get("username"))
                                    switch_target["value"] = best
                                    return
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def pump_server_to_client(reader, writer, session: dict, ctx: dict, on_status):
    """Caster -> Rover. Normalerweise werden die Bytes unveraendert
    durchgereicht und nur nebenbei mitgelesen (Antwort-Status, RTCM 1005/1006,
    Heartbeat). Bei ctx["reframe"] (/NEAR) schreibt diese Funktion Header und
    Chunk-Rahmen selbst, damit ein Upstream-Wechsel fuer den Rover unsichtbar
    bleibt.

    Schliesst den Rover-Writer NICHT; das macht handle_client."""
    reframe = ctx["reframe"]
    head = bytearray()
    head_done = False
    chunked = False
    dechunker = None
    scan = bytearray()
    last_heartbeat = 0.0

    async def send_body(body: bytes):
        if not body:
            return
        if ctx["chunked"]:
            writer.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
        else:
            writer.write(body)
        await writer.drain()

    def scan_body(body: bytes):
        global _BASE_POS_LAST
        if not body:
            return
        # Basiskoordinate nur von der eigenen Basis und hoechstens alle BASE_POS_INTERVAL_S s
        # auslesen -- sonst wird jeder Frame jedes Rovers umsonst CRC-geprueft.
        if (ctx.get("target") not in OWN_BASE_MOUNTPOINTS
                or asyncio.get_event_loop().time() - _BASE_POS_LAST < BASE_POS_INTERVAL_S):
            scan.clear()
            return
        scan.extend(body)
        if len(scan) > 65536:
            scan.clear()   # Sicherheitsnetz, falls nie ein 0xD3 gefunden wird
            return
        for payload in extract_rtcm_frames(scan):
            result = parse_rtcm_1005_1006(payload)
            if result:
                _BASE_POS_LAST = asyncio.get_event_loop().time()
                lat, lon = result
                asyncio.create_task(notify_backend("/internal/base-position", {"lat": lat, "lon": lon}))
                scan.clear()
                break

    async def heartbeat():
        nonlocal last_heartbeat
        now = asyncio.get_event_loop().time()
        if session.get("username") and not session.get("is_sourcetable") and now - last_heartbeat > 10:
            last_heartbeat = now
            asyncio.create_task(notify_backend("/internal/heartbeat", {
                "username": session["username"],
                "session_id": session["session_id"],
            }))

    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break

            body = b""
            if not head_done:
                head.extend(data)
                kind = head_kind(bytes(head))
                idx = head.find(b"\r\n\r\n")
                if kind is None or (kind and idx < 0 and len(head) < 8192):
                    if not reframe:
                        writer.write(data)
                        await writer.drain()
                    continue
                head_done = True
                if kind and idx >= 0:
                    hdr = bytes(head[:idx + 4])
                    body = bytes(head[idx + 4:])
                    chunked = bool(re.search(rb"(?im)^transfer-encoding:\s*chunked", hdr))
                    first_line = hdr.split(b"\r\n", 1)[0]
                    ok = b" 200" in first_line
                else:
                    hdr = b""
                    body = bytes(head)
                    ok = False
                if reframe and ctx["header"] is not None and not ok:
                    ctx["upstream_failed"] = True
                    return
                ctx["got_head"] = True
                if chunked:
                    dechunker = Dechunker()
                if reframe:
                    if ctx["header"] is None:
                        ctx["header"] = hdr
                        ctx["chunked"] = chunked
                        writer.write(hdr)
                        await writer.drain()
                else:
                    writer.write(data)
                    await writer.drain()
                await on_status(ok)
                payload, finished = dechunker.feed(body) if dechunker else (body, False)
                if reframe:
                    await send_body(payload)
                scan_body(payload)
                if payload:
                    await heartbeat()
                if finished:
                    break
                continue

            if not reframe:
                writer.write(data)
                await writer.drain()
            payload, finished = dechunker.feed(data) if dechunker else (data, False)
            if reframe:
                await send_body(payload)
            scan_body(payload)
            if payload:
                await heartbeat()
            if finished:
                if reframe and ctx["chunked"]:
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
                break
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass


SOURCETABLE_FILE = os.environ.get("SOURCETABLE_FILE", "/conf/sourcetable.dat")


def near_str_line() -> str:
    """STR-Zeile fuer /NEAR (aus sourcetable.dat, sonst Standardzeile). Das
    NMEA-Feld ist immer 1, damit Rover-Apps GGA senden."""
    line = None
    try:
        with open(SOURCETABLE_FILE, encoding="latin-1") as f:
            for l in f:
                l = l.strip()
                if l.startswith("STR;NEAR;"):
                    line = l
                    break
    except Exception as e:
        log.warning("Konnte %s nicht lesen: %s", SOURCETABLE_FILE, e)
    if line is None:
        lat, lon = STATION_COORDS.get(NEAREST_DEFAULT_TARGET, (52.52, 13.40))
        line = (
            "STR;NEAR;Automatische Stationswahl;RTCM 3.3;1074(1),1084(1),1094(1),1124(1),1006(1),1033(1),1230(1);"
            f"2;GPS+GLO+GAL+BDS;EigenerCaster;DEU;{lat:.4f};{lon:.4f};1;0;Auto-Select;none;B;N;3600;none"
        )
    fields = line.split(";")
    if len(fields) > 11:
        fields[11] = "1"
    return ";".join(fields)


async def serve_sourcetable(client_writer, head_bytes: bytes):
    """Holt die Sourcetable vom Caster und haengt nur die STR-Zeile fuer den
    virtuellen Mountpoint /NEAR an (der Caster kennt ihn nicht); Content-Length
    wird angepasst. Standardmaessig wird sie im NTRIP-1-Format des Casters
    ("SOURCETABLE 200 OK") geliefert, siehe unten. Die Antwort ist endlich
    (der Caster schliesst nach ENDSOURCETABLE)."""
    buf = bytearray()
    variant = SOURCETABLE_MODE
    if variant != "v2":
        # Die Lefebure-App (20260514) verwirft eine Sourcetable mit "HTTP/1.1 200 OK"
        # und fragt endlos neu an; mit der NTRIP-1-Antwort ("SOURCETABLE 200 OK")
        # des Casters klappt es. Der Stream selbst bleibt unveraendert v2.
        head_bytes = b"GET / HTTP/1.0\r\nUser-Agent: NTRIP gga-proxy/1.0\r\n\r\n"
    else:
        # Nie den Request des Rovers durchreichen, sondern immer selbst bauen
        head_bytes = (b"GET / HTTP/1.1\r\nHost: caster\r\nNtrip-Version: Ntrip/2.0\r\n"
                      b"User-Agent: NTRIP gga-proxy/1.0\r\n\r\n")
    try:
        server_reader, server_writer = await asyncio.open_connection(CASTER_HOST, CASTER_PORT)
        server_writer.write(head_bytes)
        await server_writer.drain()
        while len(buf) < 131072:
            try:
                data = await asyncio.wait_for(server_reader.read(8192), timeout=10.0)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            buf.extend(data)
        server_writer.close()
    except Exception as e:
        log.warning("Sourcetable: Caster nicht erreichbar: %s", e)
        client_writer.close()
        return

    out = bytes(buf)
    head, sep, body = out.partition(b"\r\n\r\n")
    # Backup-Stationen sind nur Ersatzquellen und werden den Rovern nicht angeboten
    hidden = {m.lstrip("/").encode() for m in FAILOVER["hidden"]}
    if sep and hidden:
        kept = [l for l in body.split(b"\r\n")
                if not (l.startswith(b"STR;") and l.split(b";")[1] in hidden)]
        new_body = b"\r\n".join(kept)
        if new_body != body:
            head = re.sub(rb"(?i)content-length:[ \t]*\d+", b"Content-Length: " + str(len(new_body)).encode(), head, count=1)
            body = new_body
            out = head + sep + body
    if sep and b"ENDSOURCETABLE" in body and b";NEAR;" not in body and b"STR;NEAR;" not in body:
        new_body = body.replace(b"ENDSOURCETABLE", near_str_line().encode("latin-1") + b"\r\nENDSOURCETABLE", 1)
        head = re.sub(
            rb"(?i)content-length:[ \t]*\d+",
            b"Content-Length: " + str(len(new_body)).encode(),
            head,
            count=1,
        )
        out = head + sep + new_body
    try:
        client_writer.write(out)
        await client_writer.drain()
    except Exception:
        pass
    finally:
        try:
            client_writer.close()
        except Exception:
            pass


async def read_request_head(reader) -> bytes | None:
    """Liest den Request-Kopf byteweise (damit nichts vom folgenden Datenstrom
    verschluckt wird), mit Zeitlimit gegen haengende Verbindungen."""
    head_buf = bytearray()
    while b"\r\n\r\n" not in head_buf and len(head_buf) < 8192:
        b = await reader.read(1)
        if not b:
            return None
        head_buf.extend(b)
    return bytes(head_buf) if b"\r\n\r\n" in head_buf else None


async def reject(writer, status: str):
    try:
        writer.write(f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
        await writer.drain()
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass


_CONN_TOTAL = 0
_CONN_PER_IP: dict = {}


async def handle_client(client_reader, client_writer):
    """Wrapper: Verbindungslimits (gesamt und pro IP) fuer den oeffentlichen Port."""
    global _CONN_TOTAL
    peer = client_writer.get_extra_info("peername")
    ip = peer[0] if peer else "unknown"
    if _CONN_TOTAL >= MAX_CONNECTIONS or _CONN_PER_IP.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
        log.warning("Verbindungslimit erreicht, lehne %s ab", ip)
        try:
            client_writer.close()
        except Exception:
            pass
        return
    _CONN_TOTAL += 1
    _CONN_PER_IP[ip] = _CONN_PER_IP.get(ip, 0) + 1
    try:
        await _handle_client(client_reader, client_writer, ip)
    except Exception:
        log.exception("Fehler bei Verbindung von %s", ip)
    finally:
        _CONN_TOTAL -= 1
        _CONN_PER_IP[ip] -= 1
        if _CONN_PER_IP[ip] <= 0:
            _CONN_PER_IP.pop(ip, None)
        try:
            client_writer.close()
        except Exception:
            pass


async def _handle_client(client_reader, client_writer, client_ip: str):
    session_id = str(uuid.uuid4())

    try:
        head_bytes = await asyncio.wait_for(read_request_head(client_reader), HEAD_TIMEOUT)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError):
        head_bytes = None
    if not head_bytes:
        client_writer.close()
        return

    first_line = head_bytes.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
    m = re.match(r"^([A-Z]+) (\S+) HTTP/1\.[01]$", first_line)
    if not m:
        await reject(client_writer, "400 Bad Request")
        return
    method, path = m.groups()
    if method != "GET":
        await reject(client_writer, "405 Method Not Allowed")
        return
    if path.lower().startswith(BLOCKED_PATHS):
        log.warning("Zugriff auf %s von %s blockiert", path[:60], client_ip)
        await reject(client_writer, "403 Forbidden")
        return
    if path != "/" and not MOUNTPOINT_RE.match(path):
        await reject(client_writer, "404 Not Found")
        return

    mountpoint, username = parse_request_head(head_bytes)
    is_sourcetable = (path == "/")
    is_nearest = (mountpoint == NEAREST_MOUNTPOINT_NAME)
    logical_target = NEAREST_DEFAULT_TARGET if is_nearest else mountpoint
    current_target = logical_target

    session = {
        "client_ip": client_ip,
        "username": username,
        "mountpoint": mountpoint,
        "session_id": session_id,
        "is_nearest": is_nearest,
        "is_sourcetable": is_sourcetable,
        "switched": False,
        "connected": False,
    }
    ctx = {"reframe": is_nearest, "header": None, "chunked": False,
           "upstream_failed": False, "got_head": False}

    if is_sourcetable:
        log.info("Sourcetable-Anfrage von %s user=%s", client_ip, username)
        await serve_sourcetable(client_writer, head_bytes)
        return
    log.info("Stream-Anfrage von %s user=%s mountpoint=%s", client_ip, username, mountpoint)

    fails = 0
    while True:
        current_target = await resolve_target(logical_target)
        if current_target != logical_target:
            log.info("Failover: %s -> %s (user=%s)", logical_target, current_target, username)
        try:
            server_reader, server_writer = await asyncio.open_connection(CASTER_HOST, CASTER_PORT)
        except Exception as e:
            log.warning("Konnte Caster nicht erreichen: %s", e)
            break

        server_writer.write(rewrite_request(head_bytes, mountpoint, current_target))
        await server_writer.drain()

        async def on_status(ok: bool):
            if ok and username:
                session["connected"] = True
                await notify_backend("/internal/connect-event", {
                    "username": username,
                    "session_id": session_id,
                    "ip": client_ip,
                    "mountpoint": current_target,
                    "requested_mountpoint": mountpoint,
                })

        switch_target = {"value": None}
        ctx["got_head"] = False
        ctx["target"] = current_target
        client_task = asyncio.create_task(pump_client_to_server(client_reader, server_writer, session, switch_target, logical_target))
        server_task = asyncio.create_task(pump_server_to_client(server_reader, client_writer, session, ctx, on_status))
        watch_task = asyncio.create_task(failover_watch(logical_target, current_target, server_writer, client_writer, session))

        done, pending = await asyncio.wait({client_task, server_task}, return_when=asyncio.FIRST_COMPLETED)
        watch_task.cancel()
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, watch_task, return_exceptions=True)
        try:
            server_writer.close()
        except Exception:
            pass

        # Nach einem Wechsel gibt der Caster den alten Slot (max_connections) oft erst
        # mit kurzer Verzoegerung frei -> kurz erneut versuchen, danach auf die
        # Default-Station zurueckfallen.
        if (is_nearest and session["switched"] and server_task in done
                and (ctx["upstream_failed"] or not ctx["got_head"])):
            ctx["upstream_failed"] = False
            fails += 1
            if fails <= 5:
                await asyncio.sleep(0.5)
                continue
            if logical_target != NEAREST_DEFAULT_TARGET:
                log.warning("Nearest: %s nicht verfuegbar, zurueck auf %s (user=%s)",
                            logical_target, NEAREST_DEFAULT_TARGET, username)
                logical_target = NEAREST_DEFAULT_TARGET
                fails = 0
                continue
        else:
            fails = 0

        if is_nearest and switch_target["value"] and switch_target["value"] != logical_target:
            log.info("Nearest-Mountpoint-Wechsel: %s -> %s (user=%s)", logical_target, switch_target["value"], username)
            logical_target = switch_target["value"]
            fails = 0
            await asyncio.sleep(0.3)
            continue  # neu verbinden, diesmal mit der naeheren Station

        break

    try:
        client_writer.close()
    except Exception:
        pass

    if session["connected"]:
        await notify_backend("/internal/disconnect-event", {"username": username, "session_id": session_id})
    log.info("Verbindung beendet: %s user=%s mountpoint=%s (zuletzt genutzt: %s)", client_ip, username, mountpoint, current_target)


async def main():
    for _ in range(30):      # Backend startet parallel -> kurz warten
        try:
            r = await http_client.post(f"{BACKEND_URL}/internal/sessions-reset", timeout=5.0)
            log.info("Alte Sessions geschlossen: %s", r.json().get("closed"))
            break
        except Exception:
            await asyncio.sleep(1)
    else:
        log.warning("Sessions-Reset nicht moeglich (Backend nicht erreichbar)")
    await load_proxy_settings()
    await load_failover_map()
    await load_station_coords()
    asyncio.create_task(refresh_station_coords())
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    log.info("GGA-Proxy lauscht auf %s:%s, leitet weiter an %s:%s", LISTEN_HOST, LISTEN_PORT, CASTER_HOST, CASTER_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
