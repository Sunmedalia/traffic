"""Attach a bounded HTTP Server API feasibility probe to a running IIS worker.

Install the experiment dependency with `python -m pip install frida==17.5.1`.
Run elevated. The --plaintext experiment also emits bounded HTTP entity bytes.
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
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--runtime-dir", type=Path, help="existing temporary directory readable by the target process identity")
    parser.add_argument("--plaintext", action="store_true", help="experimental asynchronous HTTP Server API body capture")
    parser.add_argument("--ports", default="8443")
    parser.add_argument("--request-limit", type=int, default=256 << 10)
    parser.add_argument("--response-limit", type=int, default=64 << 10)
    parser.add_argument("--control-stdin", action="store_true")
    args = parser.parse_args()
    if args.pid <= 0 or args.duration < 0:
        parser.error("PID must be positive and duration must not be negative")
    ports = [int(port) for port in args.ports.split(",")]
    if not all(1 <= port <= 65535 for port in ports):
        parser.error("ports must be between 1 and 65535")
    if not (1 <= args.request_limit <= 1 << 20 and 1 <= args.response_limit <= 1 << 20):
        parser.error("body limits must be between 1 byte and 1 MiB")
    if args.runtime_dir is not None:
        runtime_dir = args.runtime_dir.resolve(strict=True)
        if not runtime_dir.is_dir():
            parser.error("--runtime-dir must be a directory")
        os.environ["TEMP"] = str(runtime_dir)
        os.environ["TMP"] = str(runtime_dir)
    import frida

    messages = queue.Queue(maxsize=256)
    dropped = 0
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
        nonlocal dropped, queued_bytes
        size = len(data or b"")
        with dropped_lock:
            if queued_bytes + size > 8 << 20:
                dropped += 1
                return
            try:
                messages.put_nowait((message, data))
            except queue.Full:
                dropped += 1
                return
            queued_bytes += size

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
        reported_drops = 0
        try:
            session.on("detached", lambda *_: detached.set())
            source_path = Path(__file__).with_name("iis-plaintext.js") if args.plaintext else Path(__file__).with_suffix(".js")
            source = source_path.read_text(encoding="utf-8")
            if args.plaintext:
                source = source.replace("__REQUEST_LIMIT__", str(args.request_limit)).replace("__RESPONSE_LIMIT__", str(args.response_limit)).replace("__PORTS__", json.dumps(ports))
            script = session.create_script(source)
            script.on("message", receive)
            script.load()
            deadline = time.monotonic() + args.duration if args.duration else None
            size = 0
            reported_drops = 0
            while not detached.is_set() and not stop.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    message, data = messages.get(timeout=0.25)
                except queue.Empty:
                    continue
                with dropped_lock:
                    queued_bytes -= len(data or b"")
                    new_drops = dropped - reported_drops
                    reported_drops = dropped
                if new_drops:
                    output.write(json.dumps({"type": "send", "payload": {"type": "loss", "count": new_drops}}) + "\n")
                if data is not None and message.get("type") == "send":
                    message["payload"]["data_b64"] = base64.b64encode(data).decode("ascii")
                line = json.dumps(message, ensure_ascii=False) + "\n"
                size += len(line.encode("utf-8"))
                if str(args.out) != "-" and size > 16 << 20:
                    output.write(json.dumps({"type": "disk_limit", "plaintext_verified": False}) + "\n")
                    break
                output.write(line)
                output.flush()
        finally:
            try:
                if script is not None and not detached.is_set():
                    summary = script.exports_sync.finish()
                    while True:
                        try:
                            message, data = messages.get_nowait()
                        except queue.Empty:
                            break
                        if data is not None and message.get("type") == "send":
                            message["payload"]["data_b64"] = base64.b64encode(data).decode("ascii")
                        line = json.dumps(message, ensure_ascii=False) + "\n"
                        size += len(line.encode("utf-8"))
                        if str(args.out) != "-" and size > 16 << 20:
                            dropped += 1
                            continue
                        output.write(line)
                    if dropped > reported_drops:
                        output.write(json.dumps({"type": "send", "payload": {"type": "loss", "count": dropped - reported_drops}}) + "\n")
                    output.write(json.dumps(summary, ensure_ascii=False) + "\n")
                    output.flush()
            finally:
                hooks_removed = bool(locals().get("summary", {}).get("hooks_removed"))
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
                if script_unloaded:
                    def detach_session():
                        try:
                            session.detach()
                        finally:
                            done.set()
                    threading.Thread(target=detach_session, daemon=True).start()
                transport_detached = done.wait(1) if script_unloaded else False
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
