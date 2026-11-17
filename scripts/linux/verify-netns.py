#!/usr/bin/env python3
"""Verify isolated Linux network-namespace capture without container services."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def wait_for(check, processes):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if check():
            return
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("test child exited before readiness")
        time.sleep(.05)
    raise RuntimeError("test readiness timed out")


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("test child exceeded stop budget")


def fixture(port_file):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    subprocess.check_call(["ip", "link", "set", "lo", "up"])

    class Echo(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            body = self.path.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Echo)
    Path(port_file).write_text(str(server.server_port))
    server.serve_forever()


def verify(args):
    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    host_namespace = os.readlink("/proc/self/ns/net")
    service = capture = None
    service_log = (root / "service.log").open("wb")
    capture_log = (root / "capture.log").open("wb")
    try:
        service = subprocess.Popen(["unshare", "--net", sys.executable,
                                    str(Path(__file__).resolve()), "--fixture", str(root / "port")],
                                   stdout=service_log, stderr=service_log)
        wait_for(lambda: (root / "port").exists(), [service])
        target_namespace = os.readlink("/proc/{}/ns/net".format(service.pid))
        assert target_namespace != host_namespace, "fixture did not enter a new network namespace"
        port = (root / "port").read_text().strip()
        session = root / "session"
        capture = subprocess.Popen([str(Path(args.binary).resolve()), "capture", "--no-tls",
                                    "--no-detect", "--interfaces", "lo", "--ports", port,
                                    "--netns-pid", str(service.pid), "--output", str(session)],
                                   stdout=capture_log, stderr=capture_log)

        def ready():
            try:
                return json.loads((session / "status.json").read_text())["state"] == "running"
            except (OSError, ValueError, KeyError):
                return False

        wait_for(ready, [service, capture])
        assert os.readlink("/proc/{}/ns/net".format(capture.pid)) == host_namespace, "collector main thread changed namespace"
        client = "import http.client; c=http.client.HTTPConnection('127.0.0.1',{}); c.request('GET','/netns-proof'); r=c.getresponse(); assert r.status==200 and r.read()==b'/netns-proof'; c.close()".format(port)
        subprocess.check_call(["nsenter", "--target", str(service.pid), "--net", sys.executable, "-c", client])
        def records():
            return json.loads(subprocess.check_output([str(Path(args.analysis_binary).resolve()),
                                                       "requests", "--session", str(session)]))

        # libpcap delivery and the bounded SQLite batch are asynchronous.
        wait_for(lambda: len(records()) == 1, [service, capture])
        stop(capture)
        assert capture.returncode == 0, "capture failed"
        rows = records()
        assert len(rows) == 1 and rows[0]["url"] == "/netns-proof" and rows[0]["status"] == 200, rows
        assert not rows[0]["incomplete"] and not rows[0]["truncated"], rows
        assert os.readlink("/proc/self/ns/net") == host_namespace
        # The fixture must still serve after the capture socket/thread stops.
        subprocess.check_call(["nsenter", "--target", str(service.pid), "--net", sys.executable, "-c", client])
        report = {"passed": True, "host_namespace": host_namespace,
                  "target_namespace": target_namespace, "requests": 1,
                  "status": json.loads((session / "status.json").read_text())}
        (root / "report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
    finally:
        try:
            stop(capture)
        finally:
            stop(service)
            service_log.close()
            capture_log.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture":
        fixture(sys.argv[2])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--binary", required=True)
        parser.add_argument("--analysis-binary", required=True)
        parser.add_argument("--output", required=True)
        verify(parser.parse_args())
