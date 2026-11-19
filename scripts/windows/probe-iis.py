"""Host bounded Windows IIS or OpenSSL plaintext probes in a running process.

Install the dependency with `python -m pip install frida==17.5.1` and run elevated.
The default IIS mode uses HTTP Server API. probe-openssl.py selects OpenSSL.
"""

import argparse
import base64
import contextlib
import json
import os
import sys
import queue
import threading
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("iis", "openssl"), default="iis")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--library", default="")
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--runtime-dir", type=Path, help="existing temporary directory readable by the target process identity")
    parser.add_argument("--plaintext", action="store_true", help="experimental asynchronous HTTP Server API body capture")
    parser.add_argument("--ports", default="8443")
    parser.add_argument("--request-limit", type=int, default=0)
    parser.add_argument("--response-limit", type=int, default=0)
    parser.add_argument("--control-stdin", action="store_true")
    parser.add_argument("--drain-on-detach", action="store_true")
    args = parser.parse_args()
    if args.drain_on_detach and (args.backend != "openssl" or str(args.out) != "-"):
        parser.error("--drain-on-detach requires OpenSSL and stdout output")
    if args.pid <= 0 or args.duration < 0:
        parser.error("PID must be positive and duration must not be negative")
    ports = [int(port) for port in args.ports.split(",")]
    if not all(1 <= port <= 65535 for port in ports):
        parser.error("ports must be between 1 and 65535")
    if not (0 <= args.request_limit <= 1 << 20 and 0 <= args.response_limit <= 1 << 20):
        parser.error("body limits must be 0 (unlimited) or between 1 byte and 1 MiB")
    if args.runtime_dir is not None:
        runtime_dir = args.runtime_dir.resolve(strict=True)
        if not runtime_dir.is_dir():
            parser.error("--runtime-dir must be a directory")
        os.environ["TEMP"] = str(runtime_dir)
        os.environ["TMP"] = str(runtime_dir)
    import frida

    messages = queue.Queue(maxsize=256)
    dropped = 0
    reported_drops = 0
    dropped_bytes = 0
    dropped_sequence = 0
    dropped_lock = threading.Lock()
    detached = threading.Event()
    stop = threading.Event()
    queued_bytes = 0
    if args.control_stdin:
        def read_control():
            sys.stdin.readline()
            stop.set()
        threading.Thread(target=read_control, daemon=True).start()

    def receive(message, data):
        nonlocal dropped, dropped_bytes, dropped_sequence, queued_bytes
        size = len(data or b"")
        with dropped_lock:
            # Keep the loss boundary after all previously accepted messages.
            if not (args.drain_on_detach and dropped > reported_drops) and queued_bytes + size <= 8 << 20:
                try:
                    messages.put_nowait((message, data))
                except queue.Full:
                    pass
                else:
                    queued_bytes += size
                    return
            dropped += 1
            if args.drain_on_detach:
                dropped_bytes += size
                if message.get("type") == "send":
                    dropped_sequence = message["payload"].get("sequence", dropped_sequence)

    if str(args.out) == "-":
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True, write_through=True)
        destination = contextlib.nullcontext(sys.stdout)
    else:
        destination = args.out.open("x", encoding="utf-8")
    with destination as output:
        try:
            session = frida.attach(args.pid)
        except Exception as error:
            output.write(json.dumps({"type": "attach_error", "pid": args.pid,
                                     "error": type(error).__name__, "message": str(error),
                                     "plaintext_verified": False}) + "\n")
            raise SystemExit(f"Attach failed: {error}. Check that the target identity can read --runtime-dir.") from error
        script = None
        size = 0

        def forward(message, data):
            nonlocal size, queued_bytes
            with dropped_lock:
                queued_bytes -= len(data or b"")
            if data is not None and message.get("type") == "send":
                message["payload"]["data_b64"] = base64.b64encode(data).decode("ascii")
            line = json.dumps(message, ensure_ascii=False) + "\n"
            size += len(line.encode("utf-8"))
            if str(args.out) != "-" and size > 16 << 20:
                return False
            output.write(line)
            output.flush()
            return True

        def report_drops():
            nonlocal reported_drops, dropped_bytes, dropped_sequence
            with dropped_lock:
                if dropped == reported_drops or (args.drain_on_detach and not messages.empty()):
                    return
                count = dropped - reported_drops
                reported_drops = dropped
                if args.drain_on_detach:
                    event = {"type": "host_loss", "queue_dropped": count, "queue_dropped_bytes": dropped_bytes,
                             "last_sequence": dropped_sequence}
                    dropped_bytes = dropped_sequence = 0
                else:
                    event = {"type": "send", "payload": {"type": "loss", "count": count}}
            output.write(json.dumps(event) + "\n")
            output.flush()

        try:
            session.on("detached", lambda *_: detached.set())
            source_path = Path(__file__).with_name("openssl-plaintext.js") if args.backend == "openssl" else (Path(__file__).with_name("iis-plaintext.js") if args.plaintext else Path(__file__).with_suffix(".js"))
            source = source_path.read_text(encoding="utf-8")
            if args.plaintext or args.backend == "openssl":
                source = source.replace("__REQUEST_LIMIT__", str(args.request_limit)).replace("__RESPONSE_LIMIT__", str(args.response_limit)).replace("__PORTS__", json.dumps(ports))
            if args.backend == "openssl":
                profile_path = args.profile or Path(__file__).with_name("openssl-profiles.json")
                profiles = json.loads(profile_path.read_text(encoding="utf-8"))
                source = source.replace("__PROFILES__", json.dumps(profiles)).replace("__LIBRARY__", json.dumps(args.library))
            script = session.create_script(source)
            script.on("message", receive)
            script.load()
            deadline = time.monotonic() + args.duration if args.duration else None
            while not detached.is_set() and not stop.is_set():
                if args.drain_on_detach:
                    report_drops()
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    message, data = messages.get(timeout=0.25)
                except queue.Empty:
                    continue
                if not args.drain_on_detach:
                    report_drops()
                if not forward(message, data):
                    output.write(json.dumps({"type": "disk_limit", "plaintext_verified": False}) + "\n")
                    break
        finally:
            summary = None
            try:
                try:
                    if script is not None and not detached.is_set():
                        summary = script.exports_sync.finish()
                finally:
                    if summary is not None or args.drain_on_detach:
                        while True:
                            try:
                                message, data = messages.get_nowait()
                            except queue.Empty:
                                break
                            if not forward(message, data):
                                with dropped_lock:
                                    dropped += 1
                        report_drops()
                    if summary is not None:
                        output.write(json.dumps(summary, ensure_ascii=False) + "\n")
                        output.flush()
            finally:
                hooks_removed = bool((summary or {}).get("hooks_removed"))
                unloaded = threading.Event()
                unload_errors = []
                def unload_script():
                    try:
                        if script is not None and not detached.is_set():
                            script.unload()
                    except Exception as error:
                        unload_errors.append(str(error))
                    finally:
                        unloaded.set()
                threading.Thread(target=unload_script, daemon=True).start()
                script_unloaded = unloaded.wait(2) and not unload_errors
                if script_unloaded:
                    hooks_removed = True
                done = threading.Event()
                if not detached.is_set():
                    def detach_session():
                        try:
                            session.detach()
                        except Exception as error:
                            unload_errors.append(str(error))
                        finally:
                            done.set()
                    threading.Thread(target=detach_session, daemon=True).start()
                    transport_detached = done.wait(1) or detached.is_set()
                else:
                    transport_detached = True
                output.write(json.dumps({"type": "host_summary", "queue_dropped": dropped,
                                         "hooks_removed": hooks_removed, "script_unloaded": script_unloaded,
                                         "transport_detached": transport_detached,
                                         "unload_errors": unload_errors}) + "\n")
                output.flush()
                if not transport_detached:
                    # Pending IIS I/O can retain the Frida runtime after patches
                    # are restored. Do not block the collector's shutdown.
                    os._exit(0 if hooks_removed else 1)


if __name__ == "__main__":
    main()
