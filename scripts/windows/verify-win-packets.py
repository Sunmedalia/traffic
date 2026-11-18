#!/usr/bin/env python3
"""Send a controlled loopback workload or verify its raw PCAP and timestamps."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import argparse
import http.client
import json
from pathlib import Path
import re
import struct


REQUEST = re.compile(rb"^GET /win-packet-smoke-(seq|batch)-([0-9]+) HTTP/1\.[01]\r\n")
EXPECTED = {(phase.encode(), number) for phase in ("seq", "batch") for number in range(1, 101)}
NANOS = 1_000_000_000


def send(port):
    def request(marker):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", f"/win-packet-smoke-{marker}", headers={"Connection": "close"})
            response = connection.getresponse()
            response.read()
            if response.status != 404:
                raise RuntimeError(f"fixture request {marker} returned {response.status}, expected 404")
        finally:
            connection.close()

    for number in range(1, 101):
        request(f"seq-{number}")
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(request, (f"batch-{number}" for number in range(1, 101))))


def pcap_records(path):
    with path.open("rb") as file:
        header = file.read(24)
        if len(header) != 24 or header[:4] != bytes.fromhex("4d3cb2a1"):
            raise ValueError(f"{path}: expected little-endian nanosecond PCAP")
        link = struct.unpack_from("<I", header, 20)[0]
        if link != 101:
            raise ValueError(f"{path}: unexpected PCAP link type {link}")
        while record := file.read(16):
            if len(record) != 16:
                raise ValueError(f"{path}: truncated packet header")
            seconds, ns, captured, wire = struct.unpack("<IIII", record)
            if ns >= NANOS or captured > wire or captured > 256 * 1024:
                raise ValueError(f"{path}: invalid packet header fields")
            packet = file.read(captured)
            if len(packet) != captured:
                raise ValueError(f"{path}: truncated packet")
            yield seconds * NANOS + ns, packet


def marker(packet, port):
    if len(packet) < 40 or packet[0] >> 4 != 4 or packet[9] != 6:
        return None
    ip_end = (packet[0] & 15) * 4
    if ip_end < 20 or len(packet) < ip_end + 20:
        return None
    destination = struct.unpack_from("!H", packet, ip_end + 2)[0]
    if destination != port or packet[12:20] != bytes([127, 0, 0, 1] * 2):
        return None
    payload = ip_end + (packet[ip_end + 12] >> 4) * 4
    match = REQUEST.match(packet[payload:])
    return (match[1], int(match[2])) if match else None


def verify(session, port):
    manifest = json.loads((session / "manifest.json").read_text(encoding="utf-8"))
    status = json.loads((session / "status.json").read_text(encoding="utf-8"))
    lower = datetime.fromisoformat(manifest["started"].replace("Z", "+00:00")).timestamp() * NANOS - NANOS
    upper = datetime.fromisoformat(status["stopped"].replace("Z", "+00:00")).timestamp() * NANOS + NANOS
    seen = set()
    packets = 0
    for path in sorted((session / "packets").glob("*.pcap")):
        for stamp, packet in pcap_records(path):
            packets += 1
            if not lower <= stamp <= upper:
                raise ValueError(f"{path}: packet {packets} timestamp {stamp} is outside capture window")
            hit = marker(packet, port)
            if hit is not None:
                seen.add(hit)
    missing = EXPECTED - seen
    if missing:
        raise ValueError(f"raw PCAP missing {len(missing)} of {len(EXPECTED)} request IDs: {sorted(missing)[:10]}")
    print(f"Verified {packets} packet timestamps and {len(EXPECTED)} unique raw HTTP request IDs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("send", "verify"))
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--session", type=Path)
    args = parser.parse_args()
    if args.mode == "send":
        send(args.port)
    elif args.session is None:
        parser.error("verify requires --session")
    else:
        verify(args.session, args.port)


if __name__ == "__main__":
    main()
