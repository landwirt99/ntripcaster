#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 landwirt99
"""Verbindet sich wie ein echter NTRIP-Client, sammelt den rohen RTCM3-Strom
fuer ein paar Sekunden und prueft, ob alles fuer einen RTK-Fix noetige
vorhanden ist (Referenzposition 1005/1006, MSM-Beobachtungen mehrerer
Konstellationen, Wiederholrate ~1Hz)."""

import os
import socket
import base64
import time
import sys
from collections import Counter

HOST = "127.0.0.1"
PORT = 5000
MOUNTPOINT = "/RTCM32"
USER = os.environ.get("NTRIP_USER", "")
PASSWORD = os.environ.get("NTRIP_PASSWORD", "")
DURATION = 30  # Sekunden mitschneiden


def crc24q(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= (byte << 16)
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
        crc &= 0xFFFFFF
    return crc


def extract_frames(buf: bytearray):
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
        total_len = 3 + length + 3
        if len(buf) < total_len:
            break
        frame_bytes = bytes(buf[:3 + length])
        crc_bytes = buf[3 + length:total_len]
        received_crc = (crc_bytes[0] << 16) | (crc_bytes[1] << 8) | crc_bytes[2]
        if crc24q(frame_bytes) == received_crc:
            payload = bytes(buf[3:3 + length])
            msg_num = (payload[0] << 4) | (payload[1] >> 4) if len(payload) >= 2 else -1
            frames.append((msg_num, len(payload), time.time()))
            del buf[:total_len]
        else:
            del buf[:1]
    return frames


class ChunkedDecoder:
    """Entfernt HTTP-Chunked-Transfer-Encoding-Rahmen (Groesse-Hex\r\n...\r\n),
    damit der RTCM3-Parser nur die reinen Nutzdaten sieht. Sauberer State-
    Machine-Ansatz, der auch mit beliebig zerstueckelten TCP-Reads klarkommt."""

    def __init__(self):
        self.buf = bytearray()
        self.state = "size"  # "size" | "data" | "trailer"
        self.need = 0

    def feed(self, data: bytes) -> bytes:
        self.buf.extend(data)
        out = bytearray()
        while True:
            if self.state == "size":
                idx = self.buf.find(b"\r\n")
                if idx == -1:
                    break
                size_line = bytes(self.buf[:idx]).split(b";")[0].strip()
                del self.buf[:idx + 2]
                try:
                    self.need = int(size_line, 16) if size_line else 0
                except ValueError:
                    self.need = 0
                self.state = "data" if self.need > 0 else "size"
            elif self.state == "data":
                take = min(self.need, len(self.buf))
                out.extend(self.buf[:take])
                del self.buf[:take]
                self.need -= take
                if self.need == 0:
                    self.state = "trailer"
                else:
                    break  # warten auf mehr Daten
            elif self.state == "trailer":
                if len(self.buf) < 2:
                    break
                del self.buf[:2]
                self.state = "size"
        return bytes(out)


def main():
    auth = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    req = (
        f"GET {MOUNTPOINT} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Ntrip-Version: Ntrip/2.0\r\n"
        f"User-Agent: NTRIP RTK-Checker/1.0\r\n"
        f"Authorization: Basic {auth}\r\n\r\n"
    )

    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.sendall(req.encode())

    # Header lesen
    header = b""
    while b"\r\n\r\n" not in header:
        header += sock.recv(1)
    print("=== Server-Antwort-Header ===")
    print(header.decode(errors="replace"))
    is_chunked = b"transfer-encoding: chunked" in header.lower()
    print(f"(Chunked Transfer-Encoding erkannt: {is_chunked})\n")
    decoder = ChunkedDecoder() if is_chunked else None

    buf = bytearray()
    all_frames = []
    total_bytes = 0
    start = time.time()
    sock.settimeout(2)
    while time.time() - start < DURATION:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        total_bytes += len(chunk)
        payload = decoder.feed(chunk) if decoder else chunk
        buf.extend(payload)
        all_frames.extend(extract_frames(buf))

    sock.close()

    print(f"\n=== Mitschnitt: {DURATION}s, {total_bytes} Bytes, {len(all_frames)} valide Frames ===\n")

    counts = Counter(f[0] for f in all_frames)
    print("Nachrichtentyp-Haeufigkeit:")
    for msg, cnt in sorted(counts.items()):
        print(f"  {msg}: {cnt}x")

    # Bewertung
    has_ref_position = any(m in (1005, 1006) for m in counts)
    msm_gps = any(m in (1071, 1072, 1073, 1074, 1075, 1076, 1077) for m in counts)
    msm_glo = any(m in (1081, 1082, 1083, 1084, 1085, 1086, 1087) for m in counts)
    msm_gal = any(m in (1091, 1092, 1093, 1094, 1095, 1096, 1097) for m in counts)
    msm_bds = any(m in (1121, 1122, 1123, 1124, 1125, 1126, 1127) for m in counts)

    msm_total = sum(cnt for m, cnt in counts.items() if 1071 <= m <= 1127)
    msm_rate_hz = msm_total / DURATION if DURATION else 0

    print("\n=== RTK-Tauglichkeits-Check ===")
    print(f"Referenzposition (1005/1006) vorhanden:  {'JA' if has_ref_position else 'NEIN'}")
    print(f"GPS-Beobachtungen (MSM):                 {'JA' if msm_gps else 'nein'}")
    print(f"GLONASS-Beobachtungen (MSM):              {'JA' if msm_glo else 'nein'}")
    print(f"Galileo-Beobachtungen (MSM):               {'JA' if msm_gal else 'nein'}")
    print(f"BeiDou-Beobachtungen (MSM):                {'JA' if msm_bds else 'nein'}")
    print(f"MSM-Beobachtungsrate:                      {msm_rate_hz:.2f} Hz")

    verdict = has_ref_position and (msm_gps or msm_glo) and msm_rate_hz >= 0.8
    print(f"\n==> Theoretisch RTK-faehig: {'JA' if verdict else 'NEIN / fraglich'}")


if __name__ == "__main__":
    main()
