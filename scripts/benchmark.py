#!/usr/bin/env python3
"""Run on the Linux test host. Results are local JSON. No website changes."""

import argparse
import atexit
import base64
import concurrent.futures
import fcntl
import hashlib
import http.client
import json
import os
import signal
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path

acceptance_lock = open("/tmp/traffic-acceptance.lock", "a")
fcntl.flock(acceptance_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
atexit.register(acceptance_lock.close)

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument(
    "--config", type=Path, default=Path("/etc/nginx/sites-available/traffic-lab")
)
parser.add_argument("--binary", default="/opt/traffic/bin/traffic")
parser.add_argument("--output", required=True)
parser.add_argument("--seconds", type=int, default=300)
parser.add_argument("--rounds", type=int, default=3)
parser.add_argument("--rates", type=int, nargs="+", default=[20, 100])
parser.add_argument(
    "--modes",
    choices=["baseline", "packets", "tls", "full"],
    nargs="+",
    default=["baseline", "packets", "tls", "full"],
)
args = parser.parse_args()
if args.seconds < 1 or args.rounds < 1 or any(rate < 1 for rate in args.rates):
    parser.error("seconds, rounds, and rates must be positive")

active_process = None


def cleanup_process():
    if active_process is not None and active_process.poll() is None:
        active_process.terminate()
        try:
            active_process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            active_process.kill()
            active_process.wait()


atexit.register(cleanup_process)
signal.signal(signal.SIGTERM, lambda _signal, _frame: raise_exit())


def raise_exit():
    raise SystemExit(143)


root = Path(args.output)
root.mkdir(parents=True, exist_ok=True)
results = []
website_config = args.config
website_hash = hashlib.sha256(website_config.read_bytes()).hexdigest()
website_pids = subprocess.check_output(["pgrep", "-x", "nginx"]).split()


def collect_rss(process, stop, peak):
    while not stop.wait(0.1):
        try:
            pids = [process.pid]
            group = Path(f"/sys/fs/cgroup/traffic-{process.pid}")
            if (group / "cgroup.procs").exists():
                pids = list(map(int, (group / "cgroup.procs").read_text().split()))
                peak[1] = max(peak[1], int((group / "memory.peak").read_text()))
                cpu = dict(
                    line.split()
                    for line in (group / "cpu.stat").read_text().splitlines()
                )
                peak[2] = max(peak[2], int(cpu["usage_usec"]))
            else:
                for children in Path(f"/proc/{process.pid}/task").glob("*/children"):
                    pids += list(map(int, children.read_text().split()))
                pids = list(set(pids))
            rss = 0
            for pid in pids:
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        rss += int(line.split()[1])
            peak[0] = max(peak[0], rss)
        except (FileNotFoundError, ProcessLookupError):
            pass


def busy_ticks():
    values = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:]))
    return sum(values[:8]) - values[3] - values[4]


def request(index):
    start = time.monotonic()
    conn = http.client.HTTPSConnection(
        args.host, context=ssl._create_unverified_context(), timeout=5
    )
    try:
        body = json.dumps({"marker": f"benchmark-{index}", "message": "normal request"})
        conn.request("POST", "/api/echo", body, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read()
        good = response.status == 200 and json.loads(data)["body"] == body
        return time.monotonic() - start, good
    except (OSError, http.client.HTTPException, ValueError, KeyError):
        return time.monotonic() - start, False
    finally:
        conn.close()


for rate in args.rates:
    for repeat in range(args.rounds):
        for mode in args.modes:
            name = f"{rate}-{repeat}-{mode}"
            session = root / name
            process = None
            log = None
            if mode != "baseline":
                log = (root / (name + ".log")).open("w")
                command = [
                    args.binary,
                    "capture",
                    "--output",
                    str(session),
                    "--interfaces",
                    "lo",
                    "--ports",
                    "80,443",
                ]
                if mode == "packets":
                    command.append("--no-tls")
                if mode in ("packets", "tls"):
                    command.append("--no-detect")
                capture_started = time.monotonic()
                process = subprocess.Popen(
                    command, stdout=log, stderr=subprocess.STDOUT
                )
                active_process = process
                time.sleep(3)
            stop_sample = threading.Event()
            peak_rss = [0, 0, 0]
            sampler = None
            if process:
                sampler = threading.Thread(
                    target=collect_rss,
                    args=(process, stop_sample, peak_rss),
                    daemon=True,
                )
                sampler.start()
            cpu_before = busy_ticks()
            start = time.monotonic()
            futures = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                for index in range(rate * args.seconds):
                    delay = start + index / rate - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                    futures.append(pool.submit(request, index))
                samples = [future.result() for future in futures]
            elapsed = time.monotonic() - start
            cpu = (busy_ticks() - cpu_before) / os.sysconf("SC_CLK_TCK") / elapsed * 100
            rss = 0
            if process:
                pids = [process.pid]
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
                if children.exists():
                    pids += list(map(int, children.read_text().split()))
                for pid in pids:
                    status = Path(f"/proc/{pid}/status")
                    if status.exists():
                        for line in status.read_text().splitlines():
                            if line.startswith("VmRSS:"):
                                rss += int(line.split()[1])
                time.sleep(2)
                stop_sample.set()
                sampler.join()
                rss = max(rss, peak_rss[0])
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                log.close()
            latencies = sorted(sample[0] for sample in samples)
            row = {
                "mode": mode,
                "rate": rate,
                "repeat": repeat,
                "seconds": args.seconds,
                "actual_rps": len(samples) / elapsed,
                "p95_ms": latencies[int(0.95 * (len(samples) - 1))] * 1000,
                "error_rate": sum(not x[1] for x in samples) / len(samples),
                "host_cpu_one_core_percent": cpu,
                "capture_rss_kib": rss,
            }
            if process:
                row["capture_cgroup_memory_peak_bytes"] = peak_rss[1]
                row["capture_cpu_percent_of_one_core"] = (
                    peak_rss[2] / (time.monotonic() - capture_started) / 10000
                )
                row["exit_code"] = process.returncode
                row["capture"] = json.loads((session / "status.json").read_text())
                if mode in ("tls", "full"):
                    database = sqlite3.connect(session / "index.sqlite")
                    paired = 0
                    markers = set()
                    duplicates = 0
                    invalid = 0
                    for (data,) in database.execute("select data from requests"):
                        record = json.loads(data)
                        try:
                            request_body = base64.b64decode(record["request"]).split(
                                b"\r\n\r\n", 1
                            )[1]
                            marker = json.loads(request_body)["marker"]
                            response_body = base64.b64decode(record["response"]).split(
                                b"\r\n\r\n", 1
                            )[1]
                            response_marker = json.loads(
                                json.loads(response_body)["body"]
                            )["marker"]
                            if marker in markers:
                                duplicates += 1
                            markers.add(marker)
                            if record["status"] == 200 and marker == response_marker:
                                paired += 1
                            else:
                                invalid += 1
                        except (KeyError, ValueError, IndexError):
                            invalid += 1
                    row["paired_responses"] = paired
                    row["unique_request_markers"] = len(markers)
                    row["duplicate_markers"] = duplicates
                    row["invalid_or_crossed_pairs"] = invalid
                    database.close()
                    row["expected_requests"] = rate * args.seconds
            assert (
                website_hash == hashlib.sha256(website_config.read_bytes()).hexdigest()
            )
            assert (
                website_pids
                == subprocess.check_output(["pgrep", "-x", "nginx"]).split()
            )
            row["site_unchanged"] = True
            results.append(row)
            temporary = root / "results.tmp"
            temporary.write_text(json.dumps(results, indent=2))
            temporary.replace(root / "results.json")
            print(json.dumps(row), flush=True)
