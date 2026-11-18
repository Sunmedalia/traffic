#!/usr/bin/env python3
"""Exercise eCapture overload and reattachment against an isolated HTTPS fixture."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import math
import re
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time


def p99(samples):
    return round(sorted(samples)[math.ceil(len(samples) * .99) - 1], 3)


def request_ids(stream):
    markers = set()
    with stream.open("rb") as raw:
        for line in raw:
            if not line.endswith(b"\n"):
                break
            event = json.loads(line)
            if event.get("type") == "data" and event.get("direction") == "read":
                data = base64.b64decode(event["data"])
                markers.update(value.decode("ascii") for value in re.findall(
                    rb"(?:^|\r\n)x-traffic-request-id: ([a-z0-9-]+)\r\n", data, re.I))
    return markers


def peak_rss(pid):
    try:
        with Path(f"/proc/{pid}/status").open() as status:
            return next(int(line.split()[1]) for line in status if line.startswith("VmHWM:"))
    except (FileNotFoundError, ProcessLookupError, StopIteration):
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--ecapture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--burst-count", type=int, default=800)
    args = parser.parse_args()
    if args.burst_count < 1:
        parser.error("--burst-count must be positive")

    helper = Path(__file__).with_name("verify-probe-drain.py")
    fixture = runpy.run_path(str(helper))
    wait_until, send_request = fixture["wait_until"], fixture["send_request"]
    args.output.mkdir(parents=True, mode=0o700)
    cert, key, port_file = [args.output / name for name in ("cert", "key", "port")]
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)

    with (args.output / "fixture.log").open("wb") as server_log, \
            (args.output / "collector.log").open("wb") as capture_log:
        fixture_cmd = [sys.executable, str(helper), "--fixture", str(cert), str(key), str(port_file)]
        server = subprocess.Popen(fixture_cmd, stdout=server_log, stderr=server_log)
        collector = None
        try:
            wait_until(port_file.exists, [server], label="HTTPS fixture readiness")
            port = int(port_file.read_text())
            payload = "x" * (24 << 10)
            session = args.output / "session"
            stream = session / "tls" / "stream.jsonl"
            peaks, windows = [], []

            def request(marker):
                start = time.monotonic()
                send_request(port, marker, payload)
                return (time.monotonic() - start) * 1000

            def load(prefix, count):
                with ThreadPoolExecutor(max_workers=8) as pool:
                    return list(pool.map(request, (f"{prefix}-{n:04d}" for n in range(count))))

            baseline = load("baseline", 100)
            collector = subprocess.Popen([
                str(args.binary.resolve()), "capture", "--interfaces", "lo", "--ports", str(port),
                "--service", "openssl", "--pid", str(server.pid), "--ecapture", str(args.ecapture.resolve()),
                "--output", str(session), "--collector-cpu-percent", "100",
                "--collector-memory-mib", "512", "--disk-limit-mib", "512",
                "--evidence-backpressure", "drop",
            ], stdout=capture_log, stderr=capture_log)
            children = fixture["find_probe_children"]

            def attached():
                try:
                    return json.loads((session / "status.json").read_text()).get("tls") == "attached"
                except (FileNotFoundError, ValueError):
                    return False

            live = [server, collector]
            wait_until(attached, live, timeout=25, label="first probe attachment")
            probe, = children(collector.pid)
            normal = load("normal", 100)

            # Freeze just the evidence consumer. The probe and synthetic target
            # keep running, so backpressure reaches the real WebSocket queue.
            collector.send_signal(signal.SIGSTOP)
            try:
                burst = load("saturated", args.burst_count)
            finally:
                collector.send_signal(signal.SIGCONT)
            recovery_deadline = time.monotonic() + 20
            recovery_attempt = 0
            while True:
                recovery_attempt += 1
                marker = f"after-overload-{recovery_attempt}"
                request(marker)
                if stream.exists() and marker in request_ids(stream):
                    break
                if time.monotonic() >= recovery_deadline or collector.poll() is not None:
                    raise RuntimeError("no capture after sender overload")
                time.sleep(.25)
            if children(collector.pid) != [probe]:
                raise AssertionError("overload replaced the probe")

            for run in range(4):
                peaks.append(peak_rss(probe))
                old = probe
                start = time.monotonic()
                subprocess.run(["kill", "-KILL", str(old)], check=True)
                samples = []
                deadline = start + 25
                while time.monotonic() < deadline and collector.poll() is None:
                    marker = f"retry-{run}-{len(samples)}"
                    samples.append((marker, time.monotonic() - start))
                    request(marker)
                    current = children(collector.pid)
                    if len(current) == 1 and current[0] != old and attached():
                        probe = current[0]
                        for _ in range(3):
                            time.sleep(.12)
                            marker = f"retry-{run}-{len(samples)}"
                            samples.append((marker, time.monotonic() - start))
                            request(marker)
                        break
                    time.sleep(.12)
                else:
                    raise RuntimeError(f"probe did not reattach after disconnect {run + 1}")
                windows.append(samples)

            peaks.append(peak_rss(probe))
            collector.send_signal(signal.SIGINT)
            if collector.wait(timeout=35) != 0:
                raise RuntimeError("collector stopped with an error")
            request("service-after-stop")
            status = json.loads((session / "status.json").read_text())
            gaps = status.get("gap_counts", {})
            sender_gap = sum(value for name, value in gaps.items() if name.endswith("/sequence_gap/published_events"))
            retries = sum(value for name, value in gaps.items() if name.endswith("/probe_restart/attempts"))
            seen = request_ids(stream)
            detection_seconds = [round(next(seconds for marker, seconds in samples if marker in seen), 3)
                                 for samples in windows]
            report = {
                "baseline_p99_ms": p99(baseline),
                "normal_capture_p99_ms": p99(normal),
                "pressure_p99_ms": p99(burst),
                "peak_probe_rss_kib": max(peaks),
                "disconnect_to_first_persisted_request_s": detection_seconds,
                "longest_observed_reattach_window_s": max(detection_seconds),
                "sender_sequence_gaps": sender_gap,
                "probe_restarts": retries,
                "drain_state": status.get("drain_state"),
            }
            print(json.dumps(report, indent=2))
            if sender_gap <= 0 or retries != 4 or "service-after-stop" in seen:
                raise AssertionError(f"missing overload/restart evidence: {report}")
        finally:
            for proc in (collector, server):
                if proc is not None and proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    main()
