#!/usr/bin/env python3
"""Controlled lab impact benchmark for Linux and Windows.

Requires psutil in the test environment. The endpoint must implement /api/echo
and return {"body": <the exact request body>}. Never run against production.
The ledger includes every scheduled ID. Dispatched means handed to the HTTP
client, which can still fail before transmitting. With capture enabled, the
runner reconciles raw request-ID headers and offline transactions per ID.
Packet reconciliation requires tcpflow and mergecap (for rotated segments).

Fault scenarios compare the same schedule with and without a collector:
burst is a short higher-rate window; slow-disk writes to a throttled lab mount;
stop and kill collect a prefix, terminate the collector, then send a follow-up
window to check business continuity and absence of post-exit capture.
"""
import argparse
import hashlib
import http.client
import json
import math
import os
import platform
import ssl
import signal
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from impact_load import run_load
from impact_reconcile import ratio, reconcile, validate_ledger_entry


def compare(row, baseline):
    throughput, p99 = row['successful_rps'], row['p99_ms']
    before_p99 = baseline['p99_ms']
    sent, before_sent = row['requests'], baseline['requests']
    checks = {
        "throughput": throughput >= baseline["successful_rps"] * 0.97,
        "p99": p99 is not None and before_p99 is not None and p99 <= before_p99 + max(before_p99 * 0.05, 1.0),
        "target_cpu": row["target_cpu_one_core_percent"] <= baseline["target_cpu_one_core_percent"] + 5,
        "errors": sent > 0 and before_sent > 0 and row["errors"] * before_sent <= baseline["errors"] * sent,
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
                    if "run_id" in config:
                        validate_ledger_entry(event, config["run_id"], config["phase"],
                                              math.ceil(config["rate"] * config["seconds"]))
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


def capture_health(status, mode):
    """A final attached state cannot erase an earlier transport loss."""
    gaps = status.get("gap_counts", {})
    discontinuity = any(count and any(reason in key for reason in (
        "/receive_queue_overflow/", "/transport_interrupted/", "/sequence_gap/",
        "/sequence_reset_or_reorder/", "/probe_restart/", "/probe_queue_loss/",
        "/write_queue_overflow/", "/driver_buffer_overflow/", "/snapshot_truncated/",
        "/single_call_truncated/", "/evidence_queue_overflow/", "/evidence_global_budget/",
        "/evidence_write_unconfirmed/", "/receive_queue_shed/", "/drain_unconfirmed/"))
        for key, count in gaps.items())
    return ((mode == "packets" or status.get("tls") in ("attached", "active-preload"))
            and not status.get("probe_failures", 0) and not discontinuity
            and not any(status.get(name, 0) for name in ("tls_dropped", "queue_dropped", "dropped", "raw_evidence_drain_unconfirmed"))
            and not any(sample.get("overflows", 0) for sample in status.get("probe_transports", {}).values()))


def measure_write(root):
    data = bytes(256 << 10)
    with tempfile.NamedTemporaryFile(dir=root) as probe:
        start = time.monotonic()
        probe.write(data)
        probe.flush()
        os.fsync(probe.fileno())
        return {'path': str(root), 'bytes': len(data),
                'write_and_fsync_ms': (time.monotonic() - start) * 1000}


def read_status(session):
    try:
        return json.loads((session / 'status.json').read_text(encoding='utf-8'))
    except (FileNotFoundError, ValueError):
        return {}


def wait_ready(process, session, mode, endpoint, run_id, label, record):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and process.poll() is None:
        status = read_status(session)
        if status.get('state') == 'running':
            tls_state = status.get('tls')
            if mode == 'packets' or tls_state in ('attached', 'active-preload'):
                return
            if tls_state in ('listening-preload', 'starting'):
                marker = f'{run_id}-{label}-warmup-{uuid.uuid4().hex}'
                good, failure = False, ''
                try:
                    good = warmup_request(endpoint, marker)
                except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as error:
                    failure = type(error).__name__
                record({'id': marker, 'phase': label + '-warmup', 'success': good, 'error': failure})
        time.sleep(.1)
    raise RuntimeError(f'{label}: backend readiness not confirmed; see capture log')


def end_capture(process, force=False):
    action = 'already_exited'
    if process.poll() is None:
        if force:
            process.kill()
            action = 'kill'
        else:
            stop_capture(process)
            action = 'graceful'
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            action = 'graceful_timeout_then_kill'
    return {'action': action, 'exit_code': process.returncode, 'confirmed_exit_at_unix': time.time()}


def measure_load(psutil, roots, config, load_command, record, worker_log):
    samples, errors = [], set()
    cpu_last = {}
    cpu_delta = 0.0
    private_peak = None
    stop = threading.Event()
    start = time.monotonic()

    def sample():
        nonlocal cpu_delta, private_peak
        try:
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
                        cpu_delta += max(0, cpu - cpu_last[identity])
                    cpu_last[identity] = cpu
                    info = target.memory_full_info()
                    private = getattr(info, 'uss', getattr(info, 'private', None))
                    known &= private is not None
                    memory += private or 0
                except psutil.Error as error:
                    known = False
                    errors.add(type(error).__name__)
            if known:
                private_peak = max(private_peak or 0, memory)
            samples.append({'seconds': time.monotonic() - start, 'private_bytes': memory if known else None,
                            'process_count': len(processes)})
        except psutil.Error as error:
            errors.add(type(error).__name__)

    def sample_until_done():
        while not stop.wait(.5):
            sample()

    # Bookend every window, including bursts shorter than the sampling interval.
    sample()
    sampler = threading.Thread(target=sample_until_done, daemon=True)
    sampler.start()
    try:
        if load_command:
            load = external_load(load_command, config, record, worker_log)
        else:
            load = run_load(config, record)
    finally:
        stop.set()
        sampler.join(timeout=5)
        if not sampler.is_alive():
            sample()
    duration = time.monotonic() - start
    return {**load, 'business_error_rate': ratio(load['errors'], load['requests'], 'dispatched'),
            'target_cpu_one_core_percent': cpu_delta / duration * 100,
            'target_private_peak_bytes': private_peak, 'resource_samples': samples,
            'sampling_duration_seconds': duration, 'sampling_errors': sorted(errors),
            'sampling_complete': not sampler.is_alive()}


def scenario_windows(args, scenario, rate):
    if scenario == 'burst':
        return [('load', rate * args.burst_multiplier, args.burst_seconds)]
    if scenario in ('stop', 'kill'):
        duration = args.seconds / 2
        return [('before', rate, duration), ('after', rate, duration)]
    return [('load', rate, args.seconds)]


def evidence_checks(report, phases, scenario):
    first = report['windows'][phases[0]]
    unexpected = ('unexpected_raw', 'unexpected_offline')
    quality = ('raw_duplicate', 'offline_duplicate', 'unpaired', 'body_truncated', 'offline_incomplete',
               'offline_body_or_status_mismatch', 'response_without_request_id', 'offline_without_raw', *unexpected)
    required = (*quality, 'raw_missing', 'reconstruction_missing')
    if scenario == 'kill':
        # The tail may never have reached stable storage. Surviving rows must
        # still have raw evidence and a usable pair; quantify all prefix loss.
        required = ('raw_duplicate', 'offline_duplicate', 'offline_without_raw', *unexpected)
    checks = {
        'capture_reconciliation': (
            first['raw_missing']['denominator'] > 0 and
            all(first[key]['count'] == 0 for key in required) and
            (scenario == 'kill' or not report['raw_tls_partial_tail'])),
    }
    if scenario in ('stop', 'kill'):
        after = report['windows'][phases[1]]
        checks['post_exit_no_evidence'] = (
            after['raw_missing']['denominator'] > 0 and
            all(after[key]['count'] == 0 for key in ('raw_observed', 'offline_observed', *unexpected)))
        if scenario == 'kill':
            checks['forced_exit_recovered_complete_pair'] = first['complete_pair']['count'] > 0
    return checks


def run_trial(args, psutil, roots, load_command, extra, stream, ledger_path,
              run_id, label, session, mode, scenario, rate, baseline):
    def record(event):
        stream.write(json.dumps(event) + '\n')

    process, log, termination = None, None, None
    measured, planned, phases = {}, {}, []
    offset = stream.tell()
    try:
        if mode != 'baseline':
            log = (args.output / f'{label}.log').open('x', encoding='utf-8')
            command = [str(args.binary), 'capture', '--output', str(session), *extra]
            if mode == 'packets':
                command += ['--no-tls']
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == 'Windows' else 0)
            wait_ready(process, session, mode, urlsplit(args.url), run_id, label, record)
        for window, window_rate, seconds in scenario_windows(args, scenario, rate):
            phase = label if window == 'load' else f'{label}-{window}'
            url = (args.baseline_url or args.url) if mode == 'baseline' else args.url
            config = {'url': url, 'rate': window_rate, 'seconds': seconds,
                      'concurrency': args.concurrency, 'body_bytes': args.body_bytes,
                      'run_id': run_id, 'phase': phase}
            phases.append(phase)
            planned[phase] = math.ceil(window_rate * seconds)
            measured[window] = measure_load(psutil, roots, config, load_command, record,
                                            args.output / f'{phase}-load.log')
            samples = measured[window].pop('resource_samples')
            (args.output / f'{phase}-resources.json').write_text(json.dumps(samples), encoding='utf-8')
            if window == 'before' and process is not None:
                termination = end_capture(process, force=scenario == 'kill')
        if process is not None and termination is None:
            termination = end_capture(process)
    finally:
        if process is not None and process.poll() is None:
            end_capture(process)
        if log is not None:
            log.close()
    stream.flush()
    row = {'mode': mode, 'scenario': scenario, 'load_windows': measured,
           **measured.get('load', {})}
    if process is not None:
        row.update(termination=termination, exit_code=process.returncode,
                   capture_status=read_status(session), session=str(session))
    with (args.output / f'{label}-offline.log').open('x', encoding='utf-8') as log:
        try:
            if process is not None:
                subprocess.run([str(args.console), 'analyze', '--session', str(session),
                                '--request-limit', str(args.request_limit), '--response-limit', str(args.response_limit)],
                               stdout=log, stderr=subprocess.STDOUT, check=True)
            row['reconciliation'] = reconcile(
                ledger_path, offset, planned, session if process is not None else None,
                mode, run_id, args.body_bytes, args.output / f'{label}-reconciliation.jsonl', log)
        except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.CalledProcessError) as error:
            row['reconciliation_error'] = str(error)
    if process is not None:
        window_checks = {}
        for window, load in measured.items():
            before = baseline['load_windows'][window]
            checks = compare(load, before)['checks']
            checks['sampling'] = all(item['sampling_complete'] and not item['sampling_errors']
                                     for item in (load, before))
            window_checks[window] = checks
        checks = {key: all(values[key] for values in window_checks.values())
                  for key in next(iter(window_checks.values()))}
        status = row['capture_status']
        checks['capture_exit'] = (termination['action'] == 'kill' and process.returncode != 0
                                  if scenario == 'kill' else
                                  termination['action'] == 'graceful' and process.returncode == 0 and
                                  status.get('state') == 'stopped')
        checks['capture_backend'] = capture_health(status, mode)
        checks['ledger_and_offline_analysis'] = 'reconciliation_error' not in row and 'reconciliation' in baseline
        if 'reconciliation' in row:
            checks.update(evidence_checks(row['reconciliation'], phases, scenario))
        row['comparison'] = {'passed': all(checks.values()), 'checks': checks, 'window_checks': window_checks}
    elif 'reconciliation_error' in row:
        row['comparison'] = {'passed': False, 'checks': {'ledger': False}}
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--baseline-url", help="separate identical lab service for a probe-free baseline")
    parser.add_argument("--baseline-target-pid", action="append", type=int,
                        help="service PID for --baseline-url; repeat for multiple roots")
    parser.add_argument("--load-command", default="[]", help="JSON worker command, e.g. [\"ssh\",\"loadgen\",\"python3\",\"/tmp/impact_load.py\"]; config is sent on stdin")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--console", type=Path, help="traffic-console binary; defaults to collector sibling")
    parser.add_argument("--scenarios", choices=["steady", "burst", "slow-disk", "stop", "kill"],
                        nargs="+", default=["steady"])
    parser.add_argument("--burst-seconds", type=float, default=2)
    parser.add_argument("--burst-multiplier", type=float, default=2)
    parser.add_argument("--slow-output-root", type=Path,
                        help="isolated throttled output filesystem for collector sessions")
    parser.add_argument("--slow-min-write-ms", type=float, default=100,
                        help="required latency of a 256 KiB write and fsync on the slow output")
    parser.add_argument("--capture-args", default="[]", help="JSON array appended to traffic capture; never shell-evaluated")
    parser.add_argument("--target-pid", type=int, action="append", required=True, help="service PID; descendants are sampled too")
    parser.add_argument("--capacity-rps", type=float, required=True, help="independently measured baseline service capacity")
    parser.add_argument("--fractions", type=float, nargs="+", default=[0.3, 0.6, 0.8])
    parser.add_argument("--modes", choices=["packets", "tls"], nargs="+", default=["packets", "tls"])
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--body-bytes", type=int, default=1024)
    parser.add_argument("--request-limit", type=int, default=1 << 20, help="offline request body byte limit")
    parser.add_argument("--response-limit", type=int, default=1 << 20, help="offline response body byte limit")
    parser.add_argument("--output", type=Path, required=True, help="new directory")
    args = parser.parse_args()
    for value in (args.burst_seconds, args.burst_multiplier, args.slow_min_write_ms):
        if not math.isfinite(value) or value <= 0:
            parser.error('scenario limits must be finite and positive')
    if not all(0 < value <= 16 << 20 for value in (args.request_limit, args.response_limit)):
        parser.error('offline body limits must be between 1 byte and 16 MiB')
    if args.burst_multiplier <= 1:
        parser.error('--burst-multiplier must be greater than one')
    if 'slow-disk' in args.scenarios and args.slow_output_root is None:
        parser.error('slow-disk requires --slow-output-root')
    if len(set(args.scenarios)) != len(args.scenarios) or len(set(args.modes)) != len(args.modes):
        parser.error('scenarios and modes must be unique')
    if 'packets' in args.modes and any(not shutil.which(tool) for tool in ('tcpflow', 'mergecap')):
        parser.error('packet reconciliation requires tcpflow and mergecap on PATH')
    if bool(args.baseline_url) != bool(args.baseline_target_pid):
        parser.error('--baseline-url and --baseline-target-pid must be supplied together')
    for url in (args.url, args.baseline_url or args.url):
        endpoint = urlsplit(url)
        if (endpoint.scheme not in ("http", "https") or not endpoint.hostname or
                endpoint.username is not None or endpoint.fragment):
            parser.error("test endpoints must be HTTP(S) URLs without userinfo or fragment")
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
    args.console = (args.console or args.binary.with_name('traffic-console' + args.binary.suffix)).resolve(strict=True)
    args.output = args.output.resolve()
    roots = [psutil.Process(pid) for pid in args.target_pid]
    baseline_roots = [psutil.Process(pid) for pid in args.baseline_target_pid] if args.baseline_target_pid else roots
    slow_io = None
    if 'slow-disk' in args.scenarios:
        args.slow_output_root = args.slow_output_root.resolve(strict=True)
        slow_io = measure_write(args.slow_output_root)
        if slow_io['write_and_fsync_ms'] < args.slow_min_write_ms:
            parser.error(f"slow-output probe took {slow_io['write_and_fsync_ms']:.1f} ms")
    args.output.mkdir(parents=True, exist_ok=False)
    run_id = uuid.uuid4().hex
    metadata = {
        "run_id": run_id, "platform": platform.platform(), "python": platform.python_version(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "console_sha256": hashlib.sha256(args.console.read_bytes()).hexdigest(),
        "target_pids": args.target_pid, "baseline_target_pids": args.baseline_target_pid or args.target_pid,
        "capture_args": extra, "load_command": load_command,
        "capacity_rps": args.capacity_rps, "http_protocol": "HTTP/1.1",
        "seconds": args.seconds, "rounds": args.rounds, "body_bytes": args.body_bytes,
        "concurrency": args.concurrency, "scenarios": args.scenarios, "slow_io_probe": slow_io,
        "request_limit": args.request_limit, "response_limit": args.response_limit,
        "burst_seconds": args.burst_seconds, "burst_multiplier": args.burst_multiplier,
    }
    (args.output / "environment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    results = []
    ledger_path = args.output / "requests.jsonl"
    with ledger_path.open("x", encoding="utf-8") as stream:
        for fraction in args.fractions:
            rate = max(1, args.capacity_rps * fraction)
            for repeat in range(args.rounds):
                for scenario in args.scenarios:
                    baseline = None
                    for mode in ["baseline", *args.modes]:
                        label = f"{fraction}-{repeat}-{mode}"
                        if scenario != "steady":
                            label += f"-{scenario}"
                        root = args.output
                        if scenario == 'slow-disk' and mode != 'baseline':
                            root = args.slow_output_root / run_id
                        targets = baseline_roots if mode == 'baseline' else roots
                        row = run_trial(args, psutil, targets, load_command, extra, stream, ledger_path,
                                        run_id, label, root / label, mode, scenario, rate, baseline)
                        row.update(fraction=fraction, repeat=repeat)
                        if mode == 'baseline':
                            baseline = row
                        results.append(row)
                        (args.output / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
                        print(json.dumps(row), flush=True)
    if not all(row.get("comparison", {"passed": True})["passed"] for row in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
