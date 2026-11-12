#!/usr/bin/env python3
"""Small, sequential HTTP/1.x acceptance against an already running lab service."""
import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import signal
import sqlite3
import ssl
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
parser.add_argument("--binary", default="/opt/traffic/bin/traffic-services")
parser.add_argument("--service", required=True)
parser.add_argument("--ecapture", default="/opt/traffic/bin/ecapture-services")
parser.add_argument("--http-port", type=int, required=True)
parser.add_argument("--https-port", type=int, required=True)
parser.add_argument("--pid", type=int)
parser.add_argument("--java-attach", action="store_true")
parser.add_argument("--path", default="/")
parser.add_argument("--new-connections-only", action="store_true", help="record explicitly that pre-existing TLS connection coverage is not tested")
parser.add_argument("--config", type=Path, required=True)
args = parser.parse_args()
before = hashlib.sha256(args.config.read_bytes()).hexdigest()
doctor_command = [args.binary, "doctor", "--service", args.service]
if args.pid:
    doctor_command += ["--pid", str(args.pid)]
before_targets = json.loads(subprocess.check_output(doctor_command))["targets"]
before_ids = sorted(t["id"] for t in before_targets)
ctx = ssl._create_unverified_context()
existing = http.client.HTTPSConnection("127.0.0.1", args.https_port, context=ctx, timeout=10)
existing.request("GET", args.path)
existing.getresponse().read()
existing_endpoint = existing.sock.getsockname() if existing.sock else None
if args.new_connections_only:
    existing.close()
    existing_endpoint = None
command = [args.binary, "capture", "--ecapture", args.ecapture, "--service", args.service, "--ports", f"{args.http_port},{args.https_port}", "--interfaces", "lo", "--output", str(args.output)]
if args.pid:
    command += ["--pid", str(args.pid)]
if args.java_attach:
    command += ["--java-attach"]
process = subprocess.Popen(command, stdout=subprocess.DEVNULL)
expected = []
try:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("collector exited during startup")
        status = args.output / "status.json"
        if status.exists():
            state = json.loads(status.read_text())
            if any(t["state"] == "attached" for t in state.get("targets", [])):
                break
        time.sleep(0.25)
    else:
        raise RuntimeError("probe did not attach")
    for index in range(6):
        secure = index % 2 == 1
        connection = existing if index == 1 and not args.new_connections_only else (
            http.client.HTTPSConnection("127.0.0.1", args.https_port, context=ctx, timeout=10)
            if secure else http.client.HTTPConnection("127.0.0.1", args.http_port, timeout=10)
        )
        separator = "&" if "?" in args.path else "?"
        path = args.path + separator + f"capture_marker={index}"
        body = json.dumps({"message": "正常访问", "index": index}, ensure_ascii=False).encode()
        method = "POST" if index >= 4 else "GET"
        connection.request(method, path, body if method == "POST" else None, {"Content-Type": "application/json; charset=utf-8"})
        response = connection.getresponse()
        response.read()
        expected.append((path, method, response.status, secure, body))
        if index != 1:
            connection.close()
        time.sleep(0.25)
    time.sleep(2)
finally:
    existing.close()
    process.send_signal(signal.SIGINT)
    process.wait(timeout=25)
assert process.returncode == 0
assert before == hashlib.sha256(args.config.read_bytes()).hexdigest()
after_ids = sorted(t["id"] for t in json.loads(subprocess.check_output(doctor_command))["targets"])
assert set(before_ids) <= set(after_ids), (before_ids, after_ids)
with sqlite3.connect(args.output / "index.sqlite") as db:
    rows = [json.loads(r[0]) for r in db.execute("SELECT data FROM requests")]
for path, method, status, secure, body in expected:
    matches = [r for r in rows if r["url"] == path]
    assert len(matches) == 1, (path, matches)
    row = matches[0]
    assert row["status"] == status and row["method"] == method, row
    assert row.get("service") == args.service, row
    assert row.get("response") and not row["incomplete"] and not row["truncated"], row
    if method == "POST":
        assert body in base64.b64decode(row["request"])
    expected_backend = ("java-agent" if args.java_attach else "openssl") if secure else "pcap"
    assert row.get("backend") == expected_backend, row
    assert row["client"] != "unknown" and row.get("local_endpoint"), row
    if "capture_marker=1" in path and existing_endpoint:
        assert row["client"] == f"{existing_endpoint[0]}:{existing_endpoint[1]}", row
status = json.loads((args.output / "status.json").read_text())
assert status["tls_dropped"] == status["queue_dropped"] == status["dropped"] == 0, status
report = {"service": args.service, "requests": len(expected), "configuration_hash": before, "status": status, "existing_client_endpoint": existing_endpoint, "original_process_ids_preserved": True, "preexisting_connection_tested": not args.new_connections_only}
(args.output / "verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report, ensure_ascii=False, indent=2))
