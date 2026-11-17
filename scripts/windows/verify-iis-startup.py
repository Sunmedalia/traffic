"""Count every request after IIS ready, without any post-attach warmup."""

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import io
import json
import ssl
import subprocess
import time
import uuid
import zipfile
from pathlib import Path

ROOT = Path("C:/traffic-iis-startup")
SITE_ROOT = Path("C:/traffic-lab")
DURATION = 8
INTERFACES = r"\Device\NPF_Loopback"
HTTP_PORT = 8080
HTTPS_PORT = 8443
BIN = ROOT / "bin/traffic.exe"
CONSOLE = ROOT / "bin/traffic-console.exe"
PYTHON = Path("python")
PROBE = ROOT / "scripts/probe-iis.py"
CONTEXT = ssl._create_unverified_context()
TRANSPORT = "https"
PROFILE = "echo"
CONCURRENCY = 1


def connection():
    if TRANSPORT == "http":
        return http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=10)
    return http.client.HTTPSConnection(
        "127.0.0.1", HTTPS_PORT, context=CONTEXT, timeout=10
    )


def call(c, path, body=None, chunked=False):
    headers = {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-cache"}
    if chunked:
        headers["Transfer-Encoding"] = "chunked"
    c.request(
        "POST" if body is not None else "GET",
        path,
        [body[:4], body[4:]] if chunked else body,
        headers,
        encode_chunked=chunked,
    )
    endpoint = c.sock.getsockname()
    version = c.sock.version() if isinstance(c.sock, ssl.SSLSocket) else None
    r = c.getresponse()
    data = r.read()
    return {
        "url": path,
        "method": "POST" if body is not None else "GET",
        "status": r.status,
        "client": list(endpoint),
        "tls_version": version,
        "request_body": base64.b64encode(body or b"").decode(),
        "response_body": base64.b64encode(data).decode(),
    }


def sample(index, run):
    body = ("IIS启动核对 " + run + " request " + str(index)).encode("utf-8")
    if PROFILE == "echo":
        return "/api/echo", body, False, 200, body
    cases = [
        ("/api/health", None, False, 200, b"healthy"),
        ("/api/echo", body, False, 200, body),
        ("/api/echo", body * 32, True, 200, body * 32),
        ("/api/echo", b"b" * (300 << 10), False, 200, b"b" * (300 << 10)),
        ("/static.txt", None, False, 200, (SITE_ROOT / "site/static.txt").read_bytes()),
        ("/chunked", None, False, 200, b"chunk-0\nchunk-1\nchunk-2\nchunk-3\n"),
        ("/large", None, False, 200, b"x" * (128 << 10)),
        ("/missing", None, False, 404, b"not found"),
        ("/api/echo", body * 512, False, 200, body * 512),
        ("/search?q=hello", None, False, 200, b"hello"),
    ]
    return cases[(index - 1) % len(cases)]


def doctor():
    return json.loads(
        subprocess.check_output(
            [str(BIN), "doctor", "--json", "--service", "iis"], encoding="utf-8"
        )
    )


def snapshot():
    files = [
        SITE_ROOT / "site/web.config",
        SITE_ROOT / "site/App_Code/TrafficLab.cs",
        SITE_ROOT / "site/static.txt",
        Path("C:/Windows/System32/inetsrv/config/applicationHost.config"),
    ]
    return {
        "config": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        "workers": sorted(t["id"] for t in doctor().get("targets") or []),
    }


def message_body(raw, request=False):
    if request:
        raw = b"HTTP/1.1 200 OK\r\n" + raw.split(b"\r\n", 1)[1]

    class Socket:
        def makefile(self, *a):
            return io.BytesIO(raw)

    response = http.client.HTTPResponse(Socket())
    response.begin()
    return response.read()


def run_round(folder, mode, count, interval=0):
    folder.mkdir(parents=True, exist_ok=False)
    existing = connection()
    call(existing, "/api/health?before_capture=" + uuid.uuid4().hex)
    before = snapshot()
    time.sleep(0.3)
    session = folder / "session"
    ledger = []
    run = uuid.uuid4().hex[:12]
    command = [
        str(BIN),
        "capture",
        "--service",
        "iis",
        "--interfaces",
        INTERFACES,
        "--ports",
        str(HTTP_PORT) + "," + str(HTTPS_PORT),
        "--duration",
        str(DURATION) + "s",
        "--output",
        str(session),
        "--iis-probe",
        str(PROBE),
        "--iis-python",
        str(PYTHON),
        "--iis-runtime-dir",
        str(RUNTIME),
    ]
    if TRANSPORT == "https":
        command.append("--require-plaintext")
    stdout = (folder / "collector.stdout").open("wb")
    stderr = (folder / "collector.stderr").open("wb")
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("collector exited before ready")
            try:
                ready = json.loads(
                    (session / "status.json").read_text(encoding="utf-8")
                )
                if ready.get("tls") == "attached":
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.01)
        else:
            raise RuntimeError("IIS attachment timeout")
        ready_at = time.time()
        (folder / "ready-status.json").write_text(json.dumps(ready, indent=2))

        def send(index):
            path, body, chunked, expected_status, expected_body = sample(index, run)
            path += (
                ("&" if "?" in path else "?")
                + "startup="
                + run
                + "&index="
                + str(index).zfill(2)
            )
            c = existing if mode == "existing" else connection()
            try:
                item = call(c, path, body, chunked)
                item.update(
                    index=index, seconds_after_ready=round(time.time() - ready_at, 6)
                )
                assert (
                    item["status"] == expected_status
                    and base64.b64decode(item["response_body"]) == expected_body
                ), "fixture response mismatch"
                return item
            finally:
                if c is not existing:
                    c.close()
                if interval:
                    time.sleep(interval)

        if CONCURRENCY == 1:
            for index in range(1, count + 1):
                ledger.append(send(index))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
                ledger.extend(pool.map(send, range(1, count + 1)))
        (folder / "ledger.json").write_text(
            json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        process.wait(timeout=35)
    finally:
        (folder / "ledger.json").write_text(
            json.dumps(ledger, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        existing.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=15)
        stdout.close()
        stderr.close()
    assert process.returncode == 0, "collector exit " + str(process.returncode)
    assert not (session / "index.sqlite").exists(), "collector created an index"
    with (folder / "analyze.json").open("wb") as f:
        subprocess.check_call(
            [str(CONSOLE), "analyze", "--session", str(session)],
            stdout=f,
            stderr=subprocess.STDOUT,
        )
    rows = json.loads(
        subprocess.check_output(
            [str(CONSOLE), "requests", "--session", str(session)], encoding="utf-8"
        )
    )
    details = {}
    for row in rows:
        if run in row["url"]:
            details[row["id"]] = json.loads(
                subprocess.check_output(
                    [str(CONSOLE), "show", row["id"], "--session", str(session)],
                    encoding="utf-8",
                )
            )["transaction"]
    checks = []
    for item in ledger:
        matches = [r for r in details.values() if r["url"] == item["url"]]
        check = {
            "index": item["index"],
            "url": item["url"],
            "matches": len(matches),
            "captured": len(matches) == 1,
            "seconds_after_ready": item["seconds_after_ready"],
        }
        if len(matches) == 1:
            row = matches[0]
            check.update(
                complete=not row["incomplete"],
                not_truncated=not row["truncated"],
                status_matches=row["status"] == item["status"],
                backend=row.get("backend"),
            )
            try:
                check["request_body_matches"] = message_body(
                    base64.b64decode(row["request"]), request=True
                ) == base64.b64decode(item["request_body"])
                check["response_body_matches"] = message_body(
                    base64.b64decode(row["response"])
                ) == base64.b64decode(item["response_body"])
            except Exception as e:
                check["request_body_matches"] = False
                check["response_body_matches"] = False
                check["decode_error"] = str(e)
            check["passed"] = all(
                check[k]
                for k in (
                    "complete",
                    "not_truncated",
                    "status_matches",
                    "request_body_matches",
                    "response_body_matches",
                )
            ) and check["backend"] == (
                "iis-httpapi" if TRANSPORT == "https" else "pcap"
            )
        else:
            check["passed"] = False
        checks.append(check)
    raw_events = []
    for path in (session / "tls").glob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                raw_events.append(json.loads(line))
            except ValueError:
                pass
    status = json.loads((session / "status.json").read_text(encoding="utf-8"))
    after = snapshot()
    assert before == after, "IIS configuration or worker identity changed"
    report = {
        "transport": TRANSPORT,
        "profile": PROFILE,
        "concurrency": CONCURRENCY,
        "mode": mode,
        "sent": count,
        "first10_captured": sum(x["captured"] for x in checks[:10]),
        "first10_passed": sum(x["passed"] for x in checks[:10]),
        "captured": sum(x["captured"] for x in checks),
        "passed": sum(x["passed"] for x in checks),
        "missing_indices": [x["index"] for x in checks if not x["captured"]],
        "failed_indices": [x["index"] for x in checks if not x["passed"]],
        "checks": checks,
        "before": before,
        "after": after,
        "collector_exit": process.returncode,
        "status": status,
        "raw_event_lines": len(raw_events),
    }
    if details:
        row = next(iter(details.values()))
        archive = folder / "evidence.zip"
        subprocess.check_call(
            [
                str(CONSOLE),
                "export",
                row["id"],
                "--session",
                str(session),
                "--out",
                str(archive),
            ],
            stdout=subprocess.DEVNULL,
        )
        with zipfile.ZipFile(archive) as z:
            hashes = json.loads(z.read("sha256.json"))
            assert all(
                hashlib.sha256(z.read(n)).hexdigest() == v for n, v in hashes.items()
            )
        report["evidence_hashes_verified"] = True
    (folder / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "mode",
                    "sent",
                    "first10_captured",
                    "first10_passed",
                    "captured",
                    "passed",
                    "missing_indices",
                )
            },
            ensure_ascii=True,
        ),
        flush=True,
    )
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=20)
    p.add_argument("--mode", choices=["new", "existing"], default="new")
    p.add_argument("--count", type=int, default=30)
    p.add_argument("--name", default="startup-new")
    p.add_argument("--interval", type=float, default=0)
    p.add_argument("--transport", choices=["http", "https"], default="https")
    p.add_argument("--profile", choices=["echo", "mixed"], default="echo")
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--analysis-binary", type=Path, required=True)
    p.add_argument("--iis-probe", type=Path, required=True)
    p.add_argument("--iis-python", type=Path, default=Path("python"))
    p.add_argument("--runtime-dir", type=Path, required=True)
    p.add_argument("--site-root", type=Path, default=Path("C:/traffic-lab"))
    p.add_argument("--interfaces", default=INTERFACES)
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--https-port", type=int, default=8443)
    p.add_argument("--duration", type=int, default=8)
    a = p.parse_args()
    if a.rounds < 1 or a.count < 10 or a.duration < 6 or a.interval < 0:
        p.error("rounds >= 1, count >= 10, duration >= 6 and interval >= 0 required")
    if not 1 <= a.concurrency <= 16 or (a.concurrency > 1 and a.mode == "existing"):
        p.error("concurrency must be 1..16; existing connection requires concurrency 1")
    if not all(1 <= port <= 65535 for port in (a.http_port, a.https_port)):
        p.error("ports must be 1..65535")
    ROOT = a.output
    BIN = a.binary
    CONSOLE = a.analysis_binary
    PROBE = a.iis_probe
    PYTHON = a.iis_python
    SITE_ROOT = a.site_root
    RUNTIME = a.runtime_dir
    INTERFACES = a.interfaces
    DURATION = a.duration
    HTTP_PORT = a.http_port
    HTTPS_PORT = a.https_port
    TRANSPORT = a.transport
    PROFILE = a.profile
    CONCURRENCY = a.concurrency
    reports = []
    for i in range(a.rounds):
        reports.append(
            run_round(
                ROOT / a.name / ("round-" + str(i + 1).zfill(2)),
                a.mode,
                a.count,
                a.interval,
            )
        )
    summary = {
        "transport": TRANSPORT,
        "profile": PROFILE,
        "concurrency": CONCURRENCY,
        "rounds": a.rounds,
        "mode": a.mode,
        "count_per_round": a.count,
        "interval": a.interval,
        "sent": sum(r["sent"] for r in reports),
        "first10_sent": 10 * len(reports),
        "first10_captured": sum(r["first10_captured"] for r in reports),
        "first10_passed": sum(r["first10_passed"] for r in reports),
        "captured": sum(r["captured"] for r in reports),
        "passed": sum(r["passed"] for r in reports),
        "reports": reports,
    }
    (ROOT / a.name / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        "STARTUP_SERIES_COMPLETE",
        json.dumps({k: v for k, v in summary.items() if k != "reports"}),
        flush=True,
    )
    raise SystemExit(0 if summary["passed"] == summary["sent"] else 1)
