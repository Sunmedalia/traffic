#!/usr/bin/env python3
"""Functional acceptance against the existing test site on the Linux host."""

import argparse
import atexit
import base64
import concurrent.futures
import fcntl
import hashlib
import http.client
import json
import signal
import sqlite3
import ssl
import subprocess
import time
import zipfile
from pathlib import Path

acceptance_lock = open("/tmp/traffic-acceptance.lock", "a")
fcntl.flock(acceptance_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
atexit.register(acceptance_lock.close)

parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--binary", default="/opt/traffic/bin/traffic")
parser.add_argument(
    "--config", type=Path, default=Path("/etc/nginx/sites-available/traffic-lab")
)
args = parser.parse_args()
binary = args.binary
output = args.output
config = args.config
before_hash = hashlib.sha256(config.read_bytes()).hexdigest()
before_pids = subprocess.check_output(["pgrep", "-x", "nginx"]).split()
existing = http.client.HTTPSConnection(
    args.host, context=ssl._create_unverified_context(), timeout=5
)
existing.request("GET", "/api/health")
existing.getresponse().read()
existing_endpoint = existing.sock.getsockname()
process = subprocess.Popen(
    [binary, "capture", "--output", str(output), "--interfaces", "lo"],
    stdout=subprocess.DEVNULL,
)
time.sleep(4)


def send(index):
    if index % 2:
        context = ssl._create_unverified_context()
        context.minimum_version = context.maximum_version = (
            ssl.TLSVersion.TLSv1_2 if index % 4 == 1 else ssl.TLSVersion.TLSv1_3
        )
        connection = http.client.HTTPSConnection(args.host, context=context, timeout=5)
    else:
        connection = http.client.HTTPConnection(args.host, timeout=5)
    body = json.dumps({"marker": f"verify-{index}", "message": "中文验证"})
    connection.request("POST", "/api/echo", body, {"Content-Type": "application/json"})
    response = connection.getresponse()
    assert json.loads(response.read())["body"] == body
    connection.close()


try:
    existing.request("GET", "/search?q=preexisting-verify")
    existing.getresponse().read()
    assert existing.sock.getsockname() == existing_endpoint
    existing.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(send, range(100)))
    connection = http.client.HTTPSConnection(
        args.host, context=ssl._create_unverified_context(), timeout=5
    )
    for path in [
        "/search?q=union%20select%201",
        "/search?q=%252e%252e%252f%252e%252e%252fetc/passwd",
        "/search?q=hello%3Bwhoami",
        "/.env",
    ] + [f"/scan-verify-{i}" for i in range(21)]:
        connection.request("GET", path)
        connection.getresponse().read()
    connection.close()
    time.sleep(3)
finally:
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
assert process.returncode == 0
assert before_hash == hashlib.sha256(config.read_bytes()).hexdigest()
assert before_pids == subprocess.check_output(["pgrep", "-x", "nginx"]).split()
connection = sqlite3.connect(output / "index.sqlite")
rows = [json.loads(row[0]) for row in connection.execute("SELECT data FROM requests")]
assert len(rows) == 126, f"captured {len(rows)} of 126"
previous = next(row for row in rows if row["url"] == "/search?q=preexisting-verify")
assert previous["client"] == f"{existing_endpoint[0]}:{existing_endpoint[1]}", (
    "preexisting connection attribution"
)
assert all(row["status"] in (200, 404) for row in rows), "unpaired response"
for index in range(100):
    marker = f"verify-{index}"
    matches = []
    for row in rows:
        if row["method"] == "POST":
            body = json.loads(base64.b64decode(row["request"]).split(b"\r\n\r\n", 1)[1])
            if body["marker"] == marker:
                matches.append(row)
    assert len(matches) == 1, marker
    response_body = json.loads(
        base64.b64decode(matches[0]["response"]).split(b"\r\n\r\n", 1)[1]
    )
    assert json.loads(response_body["body"])["marker"] == marker, "crossed response"
alerts = {a["rule"] for row in rows for a in row.get("alerts", [])}
assert {"SQLI-001", "PATH-001", "CMD-001", "FILE-001", "SCAN-001"} <= alerts, alerts
assert not any(row.get("alerts") for row in rows if row["method"] == "POST"), (
    "normal request false positive"
)
event = next(row for row in rows if row.get("alerts"))
archive = output.parent / (output.name + "-evidence.zip")
subprocess.run(
    [binary, "export", event["id"], "--session", str(output), "--out", str(archive)],
    check=True,
)
with zipfile.ZipFile(archive) as evidence:
    hashes = json.loads(evidence.read("sha256.json"))
    assert all(
        hashlib.sha256(evidence.read(name)).hexdigest() == digest
        for name, digest in hashes.items()
    )
report = {
    "requests": len(rows),
    "paired_responses": len(rows),
    "rules": sorted(alerts),
    "site_configuration_unchanged": True,
    "site_pids_unchanged": True,
    "evidence_hashes_verified": True,
}
(output / "verification.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
