import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PROBE = Path(__file__).resolve().parent / "windows" / "probe-openssl.py"

FAKE_FRIDA = """
import os

class Script:
    def __init__(self, session):
        self.session = session

    def on(self, event, callback):
        self.message = callback

    def load(self):
        count = int(os.environ["TEST_PROBE_MESSAGES"])
        for sequence in range(1, count + 1):
            self.message({"type": "send", "payload": {"type": "data", "sequence": sequence}}, b"abc")
        self.session.detached("process-terminated", None)

class Session:
    def on(self, event, callback):
        self.detached = callback

    def create_script(self, _source):
        return Script(self)

def attach(_pid):
    return Session()
"""


class WindowsProbeDrainTest(unittest.TestCase):
    def detached_output(self, count):
        with tempfile.TemporaryDirectory() as path:
            Path(path, "frida.py").write_text(FAKE_FRIDA, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(PROBE), "--pid", "42", "--out", "-", "--drain-on-detach"],
                env={**os.environ, "PYTHONPATH": path, "TEST_PROBE_MESSAGES": str(count)},
                capture_output=True, check=True, timeout=10,
            )
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_detached_session_forwards_buffered_plaintext(self):
        messages = self.detached_output(2)
        self.assertEqual([message["type"] for message in messages], ["send", "send", "host_summary"])
        self.assertEqual([message["payload"]["data_b64"] for message in messages[:2]], ["YWJj", "YWJj"])
        self.assertTrue(messages[-1]["transport_detached"])

    def test_detached_session_reports_overflow_after_retained_data(self):
        messages = self.detached_output(259)
        self.assertEqual([message["payload"]["sequence"] for message in messages[:-2]], list(range(1, 257)))
        self.assertEqual(messages[-2], {
            "type": "host_loss", "queue_dropped": 3, "queue_dropped_bytes": 9, "last_sequence": 259,
        })
        self.assertEqual(messages[-1]["queue_dropped"], 3)


if __name__ == "__main__":
    unittest.main()
