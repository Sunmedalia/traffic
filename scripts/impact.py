#!/usr/bin/env python3
"""Controlled lab impact benchmark for Linux and Windows.

Requires psutil in the test environment. The endpoint must implement /api/echo
and return {"body": <the exact request body>}. Never run against production.
The ledger includes every attempted request and failures.
"""
import argparse
import hashlib
import http.client
import json
import math
import platform
import ssl
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from impact_load import run_load


def compare(row, baseline):
    checks = {
        "throughput": row["successful_rps"] >= baseline["successful_rps"] * 0.97,
        "p99": row["p99_ms"] <= baseline["p99_ms"] + max(baseline["p99_ms"] * 0.05, 1.0),
        "target_cpu": row["target_cpu_one_core_percent"] <= baseline["target_cpu_one_core_percent"] + 5,
        "errors": row["errors"] <= baseline["errors"],
        "generator": row["generator_dropped"] == baseline["generator_dropped"] == 0,
    }
    memory, before = row.get("target_private_peak_bytes"), baseline.get("target_private_peak_bytes")
    checks["target_private_memory"] = memory is not None and before is not None and memory <= before + (32 << 20)
    return {"passed": all(checks.values()), "checks": checks}


def stop_capture(process):
    if platform.system() == "Windows":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        process.terminate()


def warmup_request(endpoint, marker):
    """Produce traffic so a lazy preload backend can prove readiness."""
    if endpoint.scheme == "https":
        connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, timeout=1,
                                                context=ssl._create_unverified_context())
    else:
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=1)
    body = json.dumps({"marker": marker, "message": "warmup"})
    path = endpoint.path or "/"
    if endpoint.query:
        path += "?" + endpoint.query
    try:
        connection.request("POST", path, body.encode(), {"Content-Type": "application/json",
                                                       "X-Traffic-Test-ID": marker})
        response = connection.getresponse()
        data = response.read((2 << 20) + 1)
        return response.status == 200 and len(data) <= 2 << 20 and json.loads(data)["body"] == body
    finally:
        connection.close()


def external_load(command, config, record, stderr_path):
    """Run a local or SSH worker without interpolating configuration into a shell."""
    with stderr_path.open("x", encoding="utf-8") as errors:
        worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=errors, text=True)
        timeout = threading.Timer(config["seconds"] + 60, worker.kill)
        timeout.start()
        result, counts = None, {"requests": 0, "errors": 0, "generator_dropped": 0}
        try:
            worker.stdin.write(json.dumps(config) + "\n")
            worker.stdin.close()
            for line in worker.stdout:
                event = json.loads(line)
                kind = event.pop("kind", None)
                if kind == "request" and result is None:
                    record(event)
                    if event.get("sent") is False:
                        counts["generator_dropped"] += 1
                    else:
                        counts["requests"] += 1
                        counts["errors"] += not event["success"]
                elif kind == "result" and result is None:
                    result = event
                else:
                    raise RuntimeError("invalid load worker stream")
            if worker.wait() != 0 or result is None:
                raise RuntimeError("load worker failed; see " + str(stderr_path))
            if any(result.get(key) != value for key, value in counts.items()):
                raise RuntimeError("load worker result disagrees with request ledger")
            if counts["requests"] + counts["generator_dropped"] != math.ceil(config["rate"] * config["seconds"]):
                raise RuntimeError("load worker did not account for every scheduled request")
            return result
        finally:
            timeout.cancel()
            if not worker.stdin.closed:
                worker.stdin.close()
            if worker.poll() is None:
                worker.kill()
            worker.wait()
            worker.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--load-command", default="[]", help="JSON worker command, e.g. [\"ssh\",\"loadgen\",\"python3\",\"/tmp/impact_load.py\"]; config is sent on stdin")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--capture-args", default="[]", help="JSON array appended to traffic capture; never shell-evaluated")
    parser.add_argument("--target-pid", type=int, action="append", required=True, help="service PID; descendants are sampled too")
    parser.add_argument("--capacity-rps", type=float, required=True, help="independently measured baseline service capacity")
    parser.add_argument("--fractions", type=float, nargs="+", default=[0.3, 0.6, 0.8])
    parser.add_argument("--modes", choices=["packets", "tls", "full"], nargs="+", default=["packets", "tls", "full"])
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--body-bytes", type=int, default=1024)
    parser.add_argument("--output", type=Path, required=True, help="new directory")
    args = parser.parse_args()
    endpoint = urlsplit(args.url)
    if endpoint.scheme not in ("http", "https") or not endpoint.hostname or endpoint.username or endpoint.fragment:
        parser.error("--url must be an HTTP(S) URL without userinfo or fragment")
    if not all(0 < value <= 1 for value in args.fractions):
        parser.error("fractions must be in (0, 1]")
    if not math.isfinite(args.capacity_rps) or min(args.seconds, args.rounds, args.concurrency, args.capacity_rps) <= 0 or not 0 <= args.body_bytes <= 1 << 20:
        parser.error("invalid load limits")
    try:
        load_command = json.loads(args.load_command)
        if not isinstance(load_command, list) or not all(isinstance(item, str) for item in load_command):
            raise ValueError("--load-command must be a string array")
        extra = json.loads(args.capture_args)
        if not isinstance(extra, list) or not all(isinstance(item, str) for item in extra):
            raise ValueError("expected a string array")
    except ValueError as error:
        parser.error(str(error))
    if any(item.split("=", 1)[0] in ("--output", "--duration", "--no-tls", "--no-detect") for item in extra):
        parser.error("capture output, duration and mode flags are owned by the runner")
    try:
        import psutil
    except ImportError:
        parser.error("install psutil in a test-only virtual environment: python -m pip install psutil")
    args.binary = args.binary.resolve(strict=True)
    roots = [psutil.Process(pid) for pid in args.target_pid]
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {"platform": platform.platform(), "python": platform.python_version(), "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(), "target_pids": args.target_pid, "capture_args": extra, "load_command": load_command, "capacity_rps": args.capacity_rps, "http_protocol": "HTTP/1.1", "seconds": args.seconds, "rounds": args.rounds, "body_bytes": args.body_bytes, "concurrency": args.concurrency}
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    results = []
    process = None
    log = None
    ledger = (args.output / "requests.jsonl").open("x", encoding="utf-8")
    run_id = uuid.uuid4().hex
    try:
        for fraction in args.fractions:
            rate = max(1, args.capacity_rps * fraction)
            for repeat in range(args.rounds):
                baseline = None
                for mode in ["baseline", *args.modes]:
                    label = f"{fraction}-{repeat}-{mode}"
                    session = args.output / label
                    process = None
                    if mode != "baseline":
                        log = (args.output / f"{label}.log").open("x", encoding="utf-8")
                        command = [str(args.binary), "capture", "--output", str(session), *extra]
                        if mode == "packets":
                            command += ["--no-tls", "--no-detect"]
                        elif mode == "tls":
                            command += ["--no-detect"]
                        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0)
                        deadline = time.monotonic() + 30
                        ready = False
                        while time.monotonic() < deadline and process.poll() is None:
                            status = {}
                            try:
                                status = json.loads((session / "status.json").read_text(encoding="utf-8"))
                                ready = status.get("state") == "running" and (mode == "packets" or status.get("tls") in ("attached", "active-preload"))
                            except (FileNotFoundError, ValueError):
                                pass
                            if ready:
                                break
                            if mode != "packets" and status.get("state") == "running" and status.get("tls") in ("listening-preload", "starting"):
                                marker = f"{run_id}-{label}-warmup-{uuid.uuid4().hex}"
                                failure = ""
                                good = False
                                try:
                                    good = warmup_request(endpoint, marker)
                                except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
                                    failure = type(error).__name__
                                ledger.write(json.dumps({"id": marker, "phase": label + "-warmup",
                                                         "success": good, "error": failure}) + "\n")
                            time.sleep(0.1)
                        if not ready:
                            raise RuntimeError(f"{label}: backend readiness not confirmed; see capture log")
                    samples = []
                    stop = threading.Event()
                    cpu_last = {}
                    cpu_delta = [0.0]
                    private_peak = [None]
                    start = time.monotonic()

                    sampling_errors = []
                    def sample():
                        try:
                            sample_loop()
                        except psutil.Error as error:
                            sampling_errors.append(type(error).__name__)
                    def sample_loop():
                        while not stop.is_set():
                            processes = {}
                            for root in roots:
                                for target in [root, *root.children(recursive=True)]:
                                    processes[(target.pid, target.create_time())] = target
                            memory = 0
                            known = True
                            for identity, target in processes.items():
                                try:
                                    cpu = sum(target.cpu_times()[:2])
                                    if identity in cpu_last:
                                        cpu_delta[0] += max(0, cpu - cpu_last[identity])
                                    cpu_last[identity] = cpu
                                    info = target.memory_full_info()
                                    private = getattr(info, "uss", getattr(info, "private", None))
                                    known &= private is not None
                                    memory += private or 0
                                except psutil.Error as error:
                                    known = False
                                    name = type(error).__name__
                                    if name not in sampling_errors:
                                        sampling_errors.append(name)
                            if known:
                                private_peak[0] = max(private_peak[0] or 0, memory)
                            samples.append({"seconds": time.monotonic() - start, "private_bytes": memory if known else None, "process_count": len(processes)})
                            stop.wait(0.5)
                    sampler = threading.Thread(target=sample, daemon=True)
                    sampler.start()
                    def record(event):
                        ledger.write(json.dumps(event) + "\n")
                    config = {"url": args.url, "rate": rate, "seconds": args.seconds,
                              "concurrency": args.concurrency, "body_bytes": args.body_bytes,
                              "run_id": run_id, "phase": label}
                    try:
                        if load_command:
                            load = external_load(load_command, config, record,
                                                 args.output / f"{label}-load.log")
                        else:
                            load = run_load(config, record)
                    finally:
                        stop.set()
                        sampler.join(timeout=5)
                    row = {"mode": mode, "fraction": fraction, "repeat": repeat, **load,
                           "target_cpu_one_core_percent": cpu_delta[0] / (time.monotonic() - start) * 100,
                           "target_private_peak_bytes": private_peak[0],
                           "sampling_duration_seconds": time.monotonic() - start}
                    (args.output / f"{label}-resources.json").write_text(json.dumps(samples), encoding="utf-8")
                    row["sampling_errors"] = sampling_errors
                    if process:
                        stop_capture(process)
                        try:
                            process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                            raise RuntimeError(f"{label}: capture stop exceeded 30 seconds")
                        log.close()
                        log = None
                        row["exit_code"] = process.returncode
                        row["capture_status"] = json.loads((session / "status.json").read_text(encoding="utf-8"))
                        row["comparison"] = compare(row, baseline)
                        row["comparison"]["checks"]["capture_exit"] = process.returncode == 0 and row["capture_status"].get("state") == "stopped"
                        row["comparison"]["checks"]["capture_backend"] = mode == "packets" or row["capture_status"].get("tls") in ("attached", "active-preload")
                        row["comparison"]["checks"]["sampling"] = not sampling_errors and not baseline.get("sampling_errors") and not sampler.is_alive()
                        row["comparison"]["passed"] = all(row["comparison"]["checks"].values())
                    else:
                        baseline = row
                    results.append(row)
                    ledger.flush()
                    (args.output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
                    print(json.dumps(row), flush=True)
        if not all(row.get("comparison", {"passed": True})["passed"] for row in results):
            raise SystemExit(1)
    finally:
        if process is not None and process.poll() is None:
            stop_capture(process)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if log:
            log.close()
        ledger.close()


if __name__ == "__main__":
    main()
