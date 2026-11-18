"""Native collector lifecycle check for the isolated review workflow."""
import base64
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

os.umask(0o077)
collector, probe, fixture = map(lambda p: str(Path(p).resolve()), sys.argv[1:])
with tempfile.TemporaryDirectory(prefix="traffic-evidence-review-") as directory:
    root = Path(directory)
    cert, key, ports = [root / name for name in ("cert", "key", "ports")]
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    with subprocess.Popen([sys.executable, fixture, "--fixture", str(cert), str(key), str(ports), "127.0.0.1", "0"]) as server:
        try:
            for _ in range(100):
                if ports.exists():
                    break
                time.sleep(.1)
            port = json.loads(ports.read_text())[0]
            for name, stop in (("normal", signal.SIGINT), ("parent_killed", signal.SIGKILL)):
                session = root / name
                args = [collector, "capture", "--service", "openssl", "--pid", str(server.pid),
                        "--ports", str(port), "--interfaces", "lo", "--ecapture", probe,
                        "--output", str(session)]
                with (root / (name + ".log")).open("w+") as output:
                    with subprocess.Popen(args, stdout=output, stderr=output) as capture:
                        children = Path(f"/proc/{capture.pid}/task")
                        try:
                            deadline = time.monotonic() + 15
                            while time.monotonic() < deadline and capture.poll() is None:
                                try:
                                    if json.loads((session / "status.json").read_text()).get("tls") == "attached":
                                        break
                                except (OSError, ValueError):
                                    pass
                                time.sleep(.1)
                            else:
                                raise RuntimeError("eCapture did not attach")
                            pids = []
                            for task in children.glob("*/children"):
                                for pid in task.read_text().split():
                                    if os.readlink(f"/proc/{pid}/exe") == probe:
                                        pids.append(pid)
                            assert len(pids) == 1, pids
                            url = f"https://127.0.0.1:{port}/{name}"
                            for _ in range(5):
                                with urllib.request.urlopen(url, context=ssl._create_unverified_context(), timeout=2) as response:
                                    assert response.read() == ("/" + name).encode()
                            stream = session / "tls" / "stream.jsonl"
                            deadline = time.monotonic() + 4
                            while time.monotonic() < deadline:
                                if stream.exists() and any(
                                        ("/" + name).encode() in base64.b64decode(event.get("data", ""))
                                        for event in map(json.loads, stream.read_text().splitlines())
                                ):
                                    break
                                time.sleep(.1)
                            else:
                                raise RuntimeError("the fixture TLS exchange was absent from raw evidence")
                            capture.send_signal(stop)
                            assert capture.wait(timeout=15) == (0 if stop == signal.SIGINT else -signal.SIGKILL)
                            for _ in range(50):
                                state = Path(f"/proc/{pids[0]}/stat")
                                if not state.exists() or state.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                                    break
                                time.sleep(.1)
                            else:
                                raise RuntimeError("eCapture survived collector shutdown")
                            with urllib.request.urlopen(url, context=ssl._create_unverified_context(), timeout=2) as response:
                                assert response.status == 200
                            print(f"eCapture {name} passed", flush=True)
                        except BaseException:
                            output.seek(0)
                            print(output.read(), flush=True)
                            tls_log = session / "logs" / "tls.log"
                            if tls_log.exists():
                                print(tls_log.read_text(), flush=True)
                            raise
                        finally:
                            if capture.poll() is None:
                                capture.kill()
        finally:
            server.terminate()
