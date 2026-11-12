"""Run the IIS HTTP/1.1 acceptance matrix locally on the Windows test host."""

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import io
import json
import sqlite3
import ssl
import subprocess
import time
import urllib.parse
import uuid
import zipfile
from pathlib import Path


def snapshot(root, binary):
    paths = [root / "site/web.config", root / "site/App_Code/TrafficLab.cs", root / "site/static.txt",
             Path("C:/Windows/System32/inetsrv/config/applicationHost.config")]
    doctor = json.loads(subprocess.check_output([str(binary), "doctor", "--service", "iis"], encoding="utf-8"))
    workers = sorted(target["id"] for target in doctor.get("targets") or [])
    return {"configuration": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
            "workers": workers}


def connection(secure):
    if secure:
        return http.client.HTTPSConnection("127.0.0.1", 8443, timeout=10,
                                           context=ssl._create_unverified_context())
    return http.client.HTTPConnection("127.0.0.1", 8080, timeout=10)


def request(conn, path, body=None, chunked=False):
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    if chunked:
        headers["Transfer-Encoding"] = "chunked"
    conn.request("POST" if body is not None else "GET", path,
                 [body[:4], body[4:]] if chunked else body, headers, encode_chunked=chunked)
    endpoint = conn.sock.getsockname()
    tls_version = conn.sock.version() if isinstance(conn.sock, ssl.SSLSocket) else None
    response = conn.getresponse()
    data = response.read()
    return {"url": path, "status": response.status, "client_endpoint": endpoint,
            "tls_version": tls_version,
            "request_body": base64.b64encode(body or b"").decode(),
            "response_body": base64.b64encode(data).decode()}


def response_body(row):
    raw = base64.b64decode(row.get("response", ""))
    if row["truncated"]:
        return raw.split(b"\r\n\r\n", 1)[1]
    class Socket:
        def makefile(self, *_args):
            return io.BytesIO(raw)
    response = http.client.HTTPResponse(Socket())
    response.begin()
    return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--analysis-binary", type=Path, required=True)
    parser.add_argument("--iis-probe", type=Path)
    parser.add_argument("--runtime-dir", type=Path, default=Path("C:/traffic-lab/probe-runtime"))
    parser.add_argument("--root", type=Path, default=Path("C:/traffic-lab"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    expected = []
    warmups = []
    failures = []
    existing = connection(True)
    initial = request(existing, "/api/health")
    endpoint = initial["client_endpoint"]
    before = snapshot(args.root, args.binary)
    session = args.output / "session"
    marker = uuid.uuid4().hex[:12]

    def run_case(secure, index, path, body=None, chunked=False, conn=None):
        path += ("&" if "?" in path else "?") + f"case={marker}-{int(secure)}-{index}"
        client = conn or connection(secure)
        try:
            result = request(client, path, body, chunked)
            result["secure"] = secure
            return result
        finally:
            if conn is None:
                client.close()

    with (args.output / "collector.stdout").open("w", encoding="utf-8") as stdout, \
         (args.output / "collector.stderr").open("w", encoding="utf-8") as stderr:
        command = [str(args.binary), "capture", "--service", "iis",
                   "--interfaces", r"\Device\NPF_Loopback", "--ports", "8080,8443",
                   "--duration", "30s", "--output", str(session)]
        if args.iis_probe:
            command.extend(["--iis-probe", str(args.iis_probe), "--iis-runtime-dir", str(args.runtime_dir)])
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 10
            while not (session / "manifest.json").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("Collector failed to start; inspect collector.stderr")
                time.sleep(0.1)
            # The manifest precedes opening the capture handles.
            time.sleep(1)
            if args.iis_probe:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    state = json.loads((session / "status.json").read_text())
                    if state["tls"] == "attached":
                        break
                    if state["tls"] == "unavailable":
                        raise RuntimeError("IIS helper unavailable; inspect the session logs")
                    time.sleep(0.2)
                else:
                    raise RuntimeError("IIS helper did not attach")
                # Report startup receives separately from the acceptance matrix.
                for index in range(24):
                    warmups.append(run_case(True, f"warmup-{index}", "/api/health"))
                    time.sleep(0.02)
                time.sleep(0.5)
            expected.append(run_case(True, "existing", "/api/health", conn=existing))
            fixtures = [("/api/health", None, False), ("/api/echo", "正常访问中文正文".encode(), False),
                        ("/api/echo", "分块中文正文".encode(), True), ("/chunked", None, False),
                        ("/large", None, False), ("/api/echo", b"b" * (300 << 10), False),
                        ("/static.txt", None, False), ("/missing", None, False)]
            for secure in (False, True):
                for index, (path, body, chunked) in enumerate(fixtures):
                    expected.append(run_case(secure, index, path, body, chunked))
                keepalive = connection(secure)
                try:
                    for index in range(4):
                        expected.append(run_case(secure, f"keep-{index}", "/api/health", conn=keepalive))
                finally:
                    keepalive.close()
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    expected.extend(pool.map(lambda i: run_case(secure, f"parallel-{i}", "/api/health"), range(12)))
                for index, query in enumerate(["' OR 1=1--", ";cat /etc/passwd", "../../etc/passwd", "/.git/config"]):
                    expected.append(run_case(secure, f"rule-{index}", "/search?q=" + urllib.parse.quote(query)))
                for index in range(25):
                    expected.append(run_case(secure, f"scan-{index}", f"/scan-{index}"))
            process.wait(timeout=45)
        finally:
            existing.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

    after = snapshot(args.root, args.binary)
    for sample in expected:
        path = urllib.parse.urlsplit(sample["url"]).path
        expected_status = 404 if path == "/missing" or path.startswith("/scan-") else 200
        if sample["status"] != expected_status:
            failures.append({"server_status": sample["status"], "expected_status": expected_status, "url": sample["url"]})
    existing_preserved = expected[0]["client_endpoint"] == endpoint
    if not existing_preserved:
        failures.append({"preexisting_https_connection_changed": expected[0]["client_endpoint"]})
    with sqlite3.connect(session / "index.sqlite") as db:
        rows = [json.loads(data) for (data,) in db.execute("SELECT data FROM requests")]
    for sample in expected:
        if sample["secure"] and not args.iis_probe:
            continue
        matches = [r for r in rows if r["url"] == sample["url"]]
        if len(matches) != 1:
            failures.append({"url": sample["url"], "secure": sample["secure"], "matches": len(matches)})
            continue
        row = matches[0]
        request_data = base64.b64decode(sample["request_body"])
        response_data = base64.b64decode(sample["response_body"])
        oversized = len(request_data) > 256 << 10 or len(response_data) > 64 << 10
        checks = {"status": row["status"] == sample["status"], "service": row.get("service") == "iis",
                  "complete": not row["incomplete"], "truncation": row["truncated"] == oversized,
                  "response_body": response_body(row) == response_data[:64 << 10],
                  "request_body": request_data[:256 << 10] in base64.b64decode(row["request"]),
                  "backend": row.get("backend") == ("iis-httpapi" if sample["secure"] else "pcap")}
        if not all(checks.values()):
            failures.append({"url": sample["url"], "secure": sample["secure"], "checks": checks})
    status = json.loads((session / "status.json").read_text())
    if before != after:
        failures.append({"configuration_or_worker_changed": {"before": before, "after": after}})
    if process.returncode or any(status[k] for k in ("queue_dropped", "dropped", "tls_dropped")):
        failures.append({"collector_exit": process.returncode, "status": status})
    helper_summaries = []
    for path in (session / "tls").glob("iis-*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            if item.get("type") == "host_summary":
                helper_summaries.append(item)
    if args.iis_probe and (not helper_summaries or not all(item.get("hooks_removed") for item in helper_summaries)):
        failures.append({"helper_unload": "no confirmation that hooks were removed"})
    rules = sorted({alert["rule"] for row in rows for alert in row.get("alerts", [])})
    missing_rules = sorted({"SQLI-001", "CMD-001", "PATH-001", "FILE-001", "SCAN-001"} - set(rules))
    if missing_rules:
        failures.append({"missing_rules": missing_rules})
    export_rows = []
    if rows:
        export_rows.append(("evidence.zip", rows[0]))
    secure_row = next((row for row in rows if row.get("backend") == "iis-httpapi"), None)
    if secure_row:
        export_rows.append(("https-evidence.zip", secure_row))
    for archive_name, row in export_rows:
        archive = args.output / archive_name
        subprocess.run([str(args.analysis_binary), "export", row["id"], "--session", str(session), "--out", str(archive)], check=True)
        with zipfile.ZipFile(archive) as exported:
            hashes = json.loads(exported.read("sha256.json"))
            for name, digest in hashes.items():
                if hashlib.sha256(exported.read(name)).hexdigest() != digest:
                    failures.append({"evidence_hash": name})
            if row.get("backend") == "iis-httpapi":
                if exported.read("request.http") != base64.b64decode(row["request"]) or exported.read("response.http") != base64.b64decode(row["response"]):
                    failures.append({"https_evidence": "exported plaintext differs from the indexed record"})
    http_passed = not any(failure.get("secure") is not True for failure in failures)
    https_passed = bool(args.iis_probe) and not any(failure.get("secure") is not False for failure in failures)
    report = {"http_passed": http_passed, "failures": failures, "status": status,
              "requests_sent": len(expected), "http_expected": sum(not s["secure"] for s in expected),
              "https_captured": sum(":8443" in r.get("local_endpoint", "") for r in rows),
              "https_plaintext_verified": https_passed,
              "helper_summaries": helper_summaries,
              "startup_warmup_requests": len(warmups),
              "startup_warmup_captured": sum(any(r["url"] == w["url"] for r in rows) for w in warmups), "preexisting_https_endpoint": endpoint,
              "preexisting_https_connection_preserved": existing_preserved,
              "tls_versions": sorted({s["tls_version"] for s in expected if s["tls_version"]}),
              "rules": rules, "baseline": before, "after": after}
    (args.output / "client.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.output / "verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
