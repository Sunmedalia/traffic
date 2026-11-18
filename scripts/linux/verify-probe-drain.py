#!/usr/bin/env python3
"""Verify Linux eCapture and LD_PRELOAD shutdown drain boundaries in isolation.

Starts an isolated loopback HTTPS server, sends synthetic requests carrying
unique X-Traffic-Request-ID headers before, across, and after collector stop,
and verifies:
  1. Last persisted raw TLS events in tls/stream.jsonl and offline replay index.
  2. eCapture normal stop confirms DataDrained=true and drain_state=confirmed.
  3. LD_PRELOAD normal stop drains socket-buffered events while preserving
     drain_state=unverified (no reverse final-sequence handshake).
  4. Zero collector non-zero exit codes, healthy target service after stop, and
     zero residual collector/ecapture child processes.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading
import time


def run_fixture(cert, key, port_file):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            req_id = self.headers.get("X-Traffic-Request-ID", "")
            resp = json.dumps({"id": req_id, "echo": body.decode("utf-8", errors="replace")}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("X-Traffic-Reply-ID", req_id)
            self.end_headers()
            self.wfile.write(resp)

    class Server(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    srv = Server(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    Path(port_file).write_text(str(srv.server_port), encoding="utf-8")
    srv.serve_forever()


def send_request(port, req_id, payload="boundary-probe"):
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    try:
        body = f"{payload}:{req_id}".encode("utf-8")
        conn.request("POST", f"/drain/{req_id}", body=body, headers={
            "Content-Type": "text/plain",
            "X-Traffic-Request-ID": req_id,
        })
        resp = conn.getresponse()
        raw = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"unexpected status {resp.status} for {req_id}")
        parsed = json.loads(raw.decode("utf-8"))
        if parsed.get("id") != req_id:
            raise RuntimeError(f"mismatched reply for {req_id}: {parsed}")
        return True
    finally:
        conn.close()


def wait_until(predicate, processes, timeout=15.0, label="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        for proc in processes:
            if proc is not None and proc.poll() is not None:
                raise RuntimeError(f"process {proc.pid} exited early with {proc.returncode} while waiting for {label}")
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {label}")


def list_matching_pids(session_dir_str):
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
        except OSError:
            continue
        if "verify-probe-drain.py" in cmdline:
            continue
        if session_dir_str in cmdline or "bin/ecapture" in cmdline:
            found.append({"pid": pid, "cmdline": cmdline.strip()})
    return found


def extract_stream_summary(stream_path):
    req_ids = []
    events = []
    if not stream_path.exists():
        return req_ids, events
    for raw_line in stream_path.read_text(encoding="utf-8").splitlines():
        ev = json.loads(raw_line)
        events.append(ev)
        if ev.get("type") == "data" and ev.get("data"):
            decoded = base64.b64decode(ev["data"])
            for line in decoded.split(b"\r\n"):
                if line.lower().startswith(b"x-traffic-request-id:"):
                    rid = line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
                    if rid not in req_ids:
                        req_ids.append(rid)
    last_non_end = None
    last_event = events[-1] if events else None
    for ev in reversed(events):
        if ev.get("type") != "end":
            last_non_end = ev
            break
    return req_ids, {
        "total_raw_records": len(events),
        "last_event_type": last_event.get("type") if last_event else None,
        "last_event_reason": last_event.get("reason") if last_event else None,
        "last_non_end_type": last_non_end.get("type") if last_non_end else None,
        "last_persisted_request_id": req_ids[-1] if req_ids else None,
    }


def exercise_mode(mode, args, root, cert, key):
    mode_dir = root / mode
    mode_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    session_dir = mode_dir / "session"
    port_file = mode_dir / "port"
    service_log = (mode_dir / "service.log").open("wb")
    collector_log = (mode_dir / "collector.log").open("wb")
    service = collector = None
    try:
        env = os.environ.copy()
        sock_path = str(mode_dir / "preload.sock")
        if mode == "preload":
            env["LD_PRELOAD"] = str(Path(args.preload_library).resolve())
            env["TRAFFIC_OPENSSL_SOCKET"] = sock_path
        service = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--fixture", str(cert), str(key), str(port_file)],
            env=env, stdout=service_log, stderr=service_log,
        )
        wait_until(port_file.exists, [service], label=f"{mode} fixture port")
        port = int(port_file.read_text(encoding="utf-8").strip())

        cmd = [
            str(Path(args.binary).resolve()), "capture",
            "--interfaces", "lo",
            "--ports", str(port),
            "--output", str(session_dir),
            "--drain-timeout", "5s",
            "--stop-timeout", "15s",
        ]
        if mode == "preload":
            cmd.extend(["--openssl-preload-socket", sock_path])
        else:
            cmd.extend([
                "--service", "openssl",
                "--pid", str(service.pid),
                "--ecapture", str(Path(args.ecapture).resolve()),
            ])

        collector = subprocess.Popen(cmd, stdout=collector_log, stderr=collector_log)

        def is_ready():
            st = session_dir / "status.json"
            if not st.exists():
                return False
            try:
                data = json.loads(st.read_text(encoding="utf-8"))
            except ValueError:
                return False
            if data.get("state") != "running":
                return False
            if mode == "preload":
                return Path(sock_path).is_socket()
            return data.get("tls") == "attached"

        wait_until(is_ready, [service, collector], timeout=20.0, label=f"{mode} collector ready")

        pre_stop_ids = [f"{mode}-pre-{i:03d}" for i in range(1, 16)]
        for rid in pre_stop_ids:
            send_request(port, rid)

        # Fire concurrent boundary requests while delivering SIGINT to collector.
        boundary_ids = []
        boundary_lock = threading.Lock()
        stop_sender = threading.Event()

        def boundary_worker():
            idx = 0
            while not stop_sender.is_set():
                idx += 1
                rid = f"{mode}-boundary-{idx:04d}"
                send_request(port, rid)
                with boundary_lock:
                    boundary_ids.append(rid)
                time.sleep(0.01)

        worker = threading.Thread(target=boundary_worker)
        worker.start()
        time.sleep(0.08)
        collector.send_signal(signal.SIGINT)
        exit_code = collector.wait(timeout=20.0)
        stop_sender.set()
        worker.join(timeout=5.0)

        post_stop_id = f"{mode}-after-stop-001"
        send_request(port, post_stop_id)

        if exit_code != 0:
            raise RuntimeError(f"{mode} collector exited with {exit_code}")

        residuals = list_matching_pids(str(mode_dir))
        # Exclude our still-running fixture process (whose port_file is under mode_dir).
        residuals = [r for r in residuals if r["pid"] != service.pid]
        if residuals:
            raise RuntimeError(f"{mode} leaked residual processes: {residuals}")

        subprocess.check_call([
            str(Path(args.analysis_binary).resolve()), "analyze", "--session", str(session_dir)
        ])
        reconstructed = json.loads(subprocess.check_output([
            str(Path(args.analysis_binary).resolve()), "requests",
            "--session", str(session_dir), "--limit", "2000"
        ]).decode("utf-8"))

        status = json.loads((session_dir / "status.json").read_text(encoding="utf-8"))
        stream_ids, stream_meta = extract_stream_summary(session_dir / "tls" / "stream.jsonl")

        missing_pre = [rid for rid in pre_stop_ids if rid not in stream_ids]
        if missing_pre:
            raise AssertionError(f"{mode} lost pre-stop request IDs before SIGINT: {missing_pre}")
        if post_stop_id in stream_ids:
            raise AssertionError(f"{mode} recorded post-stop request {post_stop_id}")
        if stream_meta["last_event_type"] != "end":
            raise AssertionError(f"{mode} raw stream missing terminal end boundary: {stream_meta}")

        if mode == "ecapture":
            if status.get("drain_state") != "confirmed":
                raise AssertionError(f"expected ecapture drain_state=confirmed, got {status}")
            exits = status.get("probe_exits") or {}
            if not exits or not all(v.get("data_drained") for v in exits.values()):
                raise AssertionError(f"expected ecapture data_drained=true, got {exits}")
        else:
            if status.get("drain_state") != "unverified":
                raise AssertionError(f"expected preload drain_state=unverified, got {status}")
            exits = status.get("probe_exits") or {}
            if not exits or any(v.get("data_drained") for v in exits.values()):
                raise AssertionError(f"expected preload data_drained=false, got {exits}")

        if status.get("tls_coverage") != "unverified":
            raise AssertionError(f"expected tls_coverage=unverified, got {status.get('tls_coverage')}")

        return {
            "mode": mode,
            "collector_exit_code": exit_code,
            "state": status.get("state"),
            "drain_state": status.get("drain_state"),
            "tls_coverage": status.get("tls_coverage"),
            "probe_exits": status.get("probe_exits"),
            "gap_counts": status.get("gap_counts", {}),
            "pre_stop_sent": len(pre_stop_ids),
            "pre_stop_captured": len(pre_stop_ids) - len(missing_pre),
            "boundary_sent_during_stop": len(boundary_ids),
            "boundary_captured": sum(1 for rid in boundary_ids if rid in stream_ids),
            "post_stop_excluded": post_stop_id not in stream_ids,
            "reconstructed_transactions": len(reconstructed),
            "stream_summary": stream_meta,
            "residual_processes": residuals,
        }
    finally:
        for proc in (collector, service):
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        service_log.close()
        collector_log.close()


def find_probe_children(collector_pid):
    children = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
        except OSError:
            continue
        rparen = stat_text.rfind(")")
        if rparen < 0:
            continue
        fields = stat_text[rparen + 2:].split()
        if len(fields) >= 2 and int(fields[1]) == collector_pid and "ecapture" in cmdline:
            children.append(pid)
    return children


def exercise_transport_interrupt(args, root, cert, key):
    mode_dir = root / "ecapture_transport_interrupt"
    mode_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    session_dir = mode_dir / "session"
    port_file = mode_dir / "port"
    service_log = (mode_dir / "service.log").open("wb")
    collector_log = (mode_dir / "collector.log").open("wb")
    service = collector = None
    try:
        service = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--fixture", str(cert), str(key), str(port_file)],
            stdout=service_log, stderr=service_log,
        )
        wait_until(port_file.exists, [service], label="interrupt fixture port")
        port = int(port_file.read_text(encoding="utf-8").strip())
        cmd = [
            str(Path(args.binary).resolve()), "capture",
            "--interfaces", "lo",
            "--ports", str(port),
            "--output", str(session_dir),
            "--drain-timeout", "3s",
            "--stop-timeout", "10s",
            "--service", "openssl",
            "--pid", str(service.pid),
            "--ecapture", str(Path(args.ecapture).resolve()),
        ]
        collector = subprocess.Popen(cmd, stdout=collector_log, stderr=collector_log)

        def is_attached():
            st = session_dir / "status.json"
            if not st.exists():
                return False
            try:
                return json.loads(st.read_text(encoding="utf-8")).get("tls") == "attached"
            except ValueError:
                return False

        wait_until(is_attached, [service, collector], timeout=20.0, label="interrupt collector attached")
        sent_ids = [f"interrupt-pre-{i:03d}" for i in range(1, 6)]
        for rid in sent_ids:
            send_request(port, rid)
        wait_until(
            lambda: len(extract_stream_summary(session_dir / "tls" / "stream.jsonl")[0]) >= len(sent_ids),
            [service, collector], timeout=5.0, label="pre-interrupt events persisted",
        )
        probe_pids = find_probe_children(collector.pid)
        if not probe_pids:
            raise RuntimeError("expected active ecapture child process before transport interrupt")
        for pid in probe_pids:
            os.kill(pid, signal.SIGKILL)
        time.sleep(0.1)
        collector.send_signal(signal.SIGINT)
        exit_code = collector.wait(timeout=15.0)
        if exit_code != 0:
            raise RuntimeError(f"transport-interrupted collector exited with {exit_code}")

        residuals = [r for r in list_matching_pids(str(mode_dir)) if r["pid"] != service.pid]
        if residuals:
            raise RuntimeError(f"transport-interrupt leaked residual processes: {residuals}")

        status = json.loads((session_dir / "status.json").read_text(encoding="utf-8"))
        stream_ids, stream_meta = extract_stream_summary(session_dir / "tls" / "stream.jsonl")
        if status.get("drain_state") != "unverified":
            raise AssertionError(f"expected drain_state=unverified after transport interrupt, got {status}")
        exits = status.get("probe_exits") or {}
        if not exits or any(v.get("data_drained") for v in exits.values()):
            raise AssertionError(f"expected data_drained=false after transport interrupt, got {exits}")
        if stream_meta["last_event_type"] != "end":
            raise AssertionError(f"expected terminal end event after transport interrupt, got {stream_meta}")
        return {
            "collector_exit_code": exit_code,
            "drain_state": status.get("drain_state"),
            "probe_exits": exits,
            "gap_counts": status.get("gap_counts", {}),
            "captured_ids": len(stream_ids),
            "stream_summary": stream_meta,
            "residual_processes": residuals,
        }
    finally:
        for proc in (collector, service):
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        service_log.close()
        collector_log.close()


def exercise_collector_abnormal_exit(args, root, cert, key):
    mode_dir = root / "collector_abnormal_exit"
    mode_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    session_dir = mode_dir / "session"
    port_file = mode_dir / "port"
    service_log = (mode_dir / "service.log").open("wb")
    collector_log = (mode_dir / "collector.log").open("wb")
    service = collector = None
    try:
        service = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--fixture", str(cert), str(key), str(port_file)],
            stdout=service_log, stderr=service_log,
        )
        wait_until(port_file.exists, [service], label="abnormal fixture port")
        port = int(port_file.read_text(encoding="utf-8").strip())
        cmd = [
            str(Path(args.binary).resolve()), "capture",
            "--interfaces", "lo",
            "--ports", str(port),
            "--output", str(session_dir),
            "--drain-timeout", "3s",
            "--stop-timeout", "10s",
            "--service", "openssl",
            "--pid", str(service.pid),
            "--ecapture", str(Path(args.ecapture).resolve()),
        ]
        collector = subprocess.Popen(cmd, stdout=collector_log, stderr=collector_log)

        def is_attached():
            st = session_dir / "status.json"
            if not st.exists():
                return False
            try:
                return json.loads(st.read_text(encoding="utf-8")).get("tls") == "attached"
            except ValueError:
                return False

        wait_until(is_attached, [service, collector], timeout=20.0, label="abnormal collector attached")
        for i in range(1, 6):
            send_request(port, f"abnorm-pre-{i:03d}")
        probe_pids = find_probe_children(collector.pid)
        if not probe_pids:
            raise RuntimeError("expected active ecapture child process before collector SIGKILL")
        collector.kill()
        exit_code = collector.wait(timeout=10.0)
        wait_until(
            lambda: len([r for r in list_matching_pids(str(mode_dir)) if r["pid"] != service.pid]) == 0,
            [service], timeout=5.0, label="probe Pdeathsig cleanup after collector SIGKILL",
        )
        send_request(port, "abnorm-service-healthy-after-kill")
        residuals = [r for r in list_matching_pids(str(mode_dir)) if r["pid"] != service.pid]
        return {
            "collector_exit_code": exit_code,
            "reaped_probe_pids": probe_pids,
            "service_healthy_after_collector_kill": True,
            "residual_processes": residuals,
        }
    finally:
        for proc in (collector, service):
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        service_log.close()
        collector_log.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture":
        run_fixture(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--analysis-binary", required=True)
    parser.add_argument("--ecapture", default="")
    parser.add_argument("--preload-library", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    results = {}
    if args.ecapture:
        results["ecapture"] = exercise_mode("ecapture", args, root, cert, key)
        results["ecapture_transport_interrupt"] = exercise_transport_interrupt(args, root, cert, key)
        results["collector_abnormal_exit"] = exercise_collector_abnormal_exit(args, root, cert, key)
    if args.preload_library:
        results["preload"] = exercise_mode("preload", args, root, cert, key)
    if not results:
        raise RuntimeError("specify at least one of --ecapture or --preload-library")

    report = {
        "passed": True,
        "kernel": os.uname().release,
        "arch": os.uname().machine,
        "results": results,
    }
    (root / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
