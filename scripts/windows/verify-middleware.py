"""Verify live Windows Nginx/Apache HTTP and OpenSSL HTTPS capture.

Requires the loopback echo fixture and middleware listeners configured before
capture. This verifier reads process identities and configuration hashes and
never starts, restarts, or reconfigures the middleware.
"""
import argparse
import base64
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import sqlite3
import ssl
import subprocess
import time
import threading
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--probe", type=Path, default=Path(__file__).with_name("probe-openssl.py"))
    parser.add_argument("--runtime-dir", default="C:/traffic-lab/probe-runtime")
    parser.add_argument("--service", choices=("auto", "nginx", "apache"), default="auto")
    parser.add_argument("--config", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = str(args.binary.resolve())
    def targets():
        return json.loads(subprocess.check_output([binary, "doctor", "--service", args.service], encoding="utf-8"))["targets"]
    before = targets()
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in args.config}
    selected = [("nginx", 18080, 18443), ("apache", 18081, 18444)]
    if args.service != "auto":
        selected = [item for item in selected if item[0] == args.service]
    marker = uuid.uuid4().hex[:12]
    expected = []
    failures = []
    tls_versions = set()
    def connect(port, secure, version=None):
        if not secure:
            return http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        context = ssl._create_unverified_context()
        if version is not None:
            context.minimum_version = context.maximum_version = version
        return http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
    def request(connection, service, secure, label, method="GET", body=None):
        path = f"/{label}?probe={marker}-{service}-{secure}-{label}"
        connection.request(method, path, body=body, headers={"Content-Type": "text/plain; charset=utf-8"})
        version = connection.sock.version() if secure else None
        response = connection.getresponse()
        data = response.read()
        if secure:
            tls_versions.add(version)
        sample = {"path": path, "service": service, "secure": secure, "method": method,
                  "status": response.status, "request": base64.b64encode(body or b"").decode(),
                  "response": base64.b64encode(data).decode(), "tls": version}
        expected.append(sample)
    existing = []
    for service, _, port in selected:
        connection = connect(port, True, ssl.TLSVersion.TLSv1_2)
        connection.request("GET", "/before-attachment")
        connection.getresponse().read()
        existing.append((service, connection))
    keepalive_stop = threading.Event()
    keepalive_errors = []
    warmup = []
    def keepalive(service, connection):
        try:
            while not keepalive_stop.wait(0.5):
                connection.request("GET", "/attach-warmup")
                connection.getresponse().read()
                warmup.append(service)
        except Exception as error:
            keepalive_errors.append(str(error))
    keepalive_threads = [threading.Thread(target=keepalive, args=item) for item in existing]
    for thread in keepalive_threads:
        thread.start()
    session = args.output / "session"
    with (args.output / "collector.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen([binary, "capture", "--service", args.service, "--ports", "18080,18081,18443,18444",
            "--interfaces", r"\Device\NPF_Loopback", "--openssl-probe", str(args.probe.resolve()),
            "--probe-runtime-dir", args.runtime_dir, "--output", str(session.resolve()), "--duration", "65s"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("collector exited before attachment")
                try:
                    status = json.loads((session / "status.json").read_text(encoding="utf-8"))
                    attached = {target["service"] for target in status.get("targets", []) if target["state"] == "attached"}
                    if all(service in attached for service, _, _ in selected):
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.25)
            else:
                raise RuntimeError("OpenSSL probes did not attach within 30 seconds")
            keepalive_stop.set()
            for thread in keepalive_threads:
                thread.join(timeout=15)
            if keepalive_errors or any(thread.is_alive() for thread in keepalive_threads):
                raise RuntimeError(f"existing connection keepalive failed: {keepalive_errors}")
            for service, connection in existing:
                request(connection, service, True, "existing")
                connection.close()
            for service, http_port, https_port in selected:
                for secure, port in [(False, http_port), (True, https_port)]:
                    for version in ([ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3] if secure else [None]):
                        connection = connect(port, secure, version)
                        for label, method, body in [("echo", "POST", "中文正文".encode()), ("chunked", "GET", None),
                                                   ("head", "HEAD", None), ("missing", "GET", None), ("large", "GET", None), ("attack", "POST", b"id=1 OR 1=1")]:
                            request(connection, service, secure, f"{label}/{version}", method, body)
                        connection.close()
                def concurrent_request(index):
                    with contextlib.closing(connect(https_port, True)) as connection:
                        request(connection, service, True, f"parallel/{index}", "POST", f"concurrent-{index}".encode())
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(concurrent_request, range(12)))
            process.wait(timeout=90)
            if process.returncode:
                raise RuntimeError(f"collector exited {process.returncode}")
        except Exception as error:
            failures.append({"reason": type(error).__name__, "message": str(error)})
        finally:
            keepalive_stop.set()
            for thread in keepalive_threads:
                thread.join(timeout=15)
            for _, connection in existing:
                connection.close()
            if process.poll() is None:
                # The fixed capture duration provides the normal graceful stop.
                process.wait(timeout=90)
    after = targets()
    if {target["id"] for target in before} != {target["id"] for target in after}:
        failures.append({"reason": "middleware process identities changed"})
    if hashes != {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in args.config}:
        failures.append({"reason": "middleware configuration changed"})
    with sqlite3.connect(session / "index.sqlite") as database:
        rows = [json.loads(row[0]) for row in database.execute("SELECT data FROM requests")]
    for sample in expected:
        matches = [row for row in rows if row.get("url") == sample["path"] and row.get("backend") == ("openssl" if sample["secure"] else "pcap")]
        if len(matches) != 1:
            failures.append({"sample": sample["path"], "reason": f"expected one capture, found {len(matches)}"})
            continue
        row = matches[0]
        request_data = base64.b64decode(row.get("request", ""))
        response_data = base64.b64decode(row.get("response", ""))
        body = base64.b64decode(sample["response"])
        checks = {"service": row.get("service") == sample["service"], "status": row.get("status") == sample["status"],
                  "request_body": base64.b64decode(sample["request"]) in request_data,
                  "response_body": (body[:65536] in response_data if body else True),
                  "complete": not row.get("incomplete", False) if len(body) <= 65536 else row.get("truncated", False)}
        if "/attack/" in sample["path"]:
            checks["detection"] = any(alert.get("rule") == "SQLI-001" for alert in row.get("alerts", []))
        if not all(checks.values()):
            failures.append({"sample": sample["path"], "checks": checks})
    summaries = []
    for path in (session / "tls").glob("openssl-*.jsonl"):
        messages = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        summaries.extend(message for message in messages if message.get("type") == "host_summary")
    if not summaries or not all(summary.get("hooks_removed") for summary in summaries):
        failures.append({"reason": "missing hook restoration confirmation"})
    report = {"warmup_requests": len(warmup), "passed": not failures, "expected": len(expected), "records": len(rows), "tls_versions": sorted(tls_versions),
              "failures": failures, "before": before, "after": after, "config_hashes": hashes, "helpers": summaries,
              "status": json.loads((session / "status.json").read_text(encoding="utf-8"))}
    (args.output / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
