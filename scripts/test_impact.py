"""Acceptance threshold boundaries must not silently treat missing metrics as zero."""
import unittest
import json
import threading
import sys
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from impact import compare, warmup_request, external_load, capture_health
from impact_load import LatencyHistogram


class ImpactChecks(unittest.TestCase):
    def setUp(self):
        self.baseline = dict(successful_rps=100, p99_ms=10,
                             target_cpu_one_core_percent=20, errors=0,
                             generator_dropped=0, target_private_peak_bytes=100 << 20)

    def test_recovered_backend_does_not_erase_transport_failure(self):
        self.assertTrue(capture_health({"tls": "attached"}, "tls"))
        for extra in ({"probe_failures": 1},
                      {"gap_counts": {"ecapture/receive_queue_overflow/transports": 1}},
                      {"gap_counts": {"ecapture/sequence_gap/published_events": 2}},
                      {"probe_transports": {"probe": {"overflows": 1}}},
                      {"tls_dropped": 1}):
            self.assertFalse(capture_health(dict(tls="attached", **extra), "full"))
        self.assertFalse(capture_health({"tls": "unavailable"}, "tls"))
        self.assertTrue(capture_health({"tls": "disabled"}, "packets"))

    def test_threshold_edges(self):
        row = dict(self.baseline, successful_rps=97, p99_ms=11,
                   target_cpu_one_core_percent=25,
                   target_private_peak_bytes=132 << 20)
        self.assertTrue(compare(row, self.baseline)["passed"])
        row["p99_ms"] = 11.01
        self.assertFalse(compare(row, self.baseline)["passed"])

    def test_missing_memory_and_generator_overload_fail(self):
        for change in ({"target_private_peak_bytes": None}, {"generator_dropped": 1}, {"errors": 1}):
            self.assertFalse(compare(dict(self.baseline, **change), self.baseline)["passed"])

    def test_quantiles_bound_error_without_retaining_each_request(self):
        histogram = LatencyHistogram()
        values = [0, .001, .12, 1, 25, 1000, 10000]
        for value in values:
            histogram.add(value)
        for fraction in (0, .5, .95, .99, 1):
            expected = values[int((len(values) - 1) * fraction)]
            actual = histogram.quantile(fraction)
            self.assertGreaterEqual(actual, expected)
            self.assertLessEqual(actual, expected * 1.001 + .001)
        for _ in range(100000):
            histogram.add(1)
        self.assertEqual(len(histogram.buckets), len(values))

    def test_external_worker_preserves_request_ledger(self):
        class Echo(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                response = json.dumps({"body": body.decode()}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            config = {"url": f"http://127.0.0.1:{server.server_port}/api/echo",
                      "rate": 20, "seconds": .2, "concurrency": 4, "body_bytes": 1024,
                      "run_id": "worker-test", "phase": "baseline"}
            ledger = []
            with tempfile.TemporaryDirectory() as folder:
                result = external_load([sys.executable, str(Path(__file__).with_name("impact_load.py"))],
                                       config, ledger.append, Path(folder) / "worker.log")
            self.assertEqual(result["requests"], 4)
            self.assertEqual(result["errors"], 0)
            self.assertEqual(result["generator_dropped"], 0)
            self.assertEqual({entry["id"] for entry in ledger},
                             {f"worker-test-baseline-{i}" for i in range(4)})
            self.assertTrue(all(entry["success"] for entry in ledger))
            self.assertEqual(len(result["worker"]["source_sha256"]), 64)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_external_worker_rejects_truncated_ledger(self):
        command = [sys.executable, "-c", 'import sys; sys.stdin.readline(); print(\'{"kind":"result","requests":1,"errors":0,"generator_dropped":0}\')']
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError, "disagrees"):
                external_load(command, {"seconds": .1, "rate": 10}, lambda _: None,
                              Path(folder) / "worker.log")

    def test_preload_warmup_sends_verifiable_request(self):
        received = []

        class Echo(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, self.headers["X-Traffic-Test-ID"], json.loads(body)))
                response = json.dumps({"body": body.decode()}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            endpoint = urlsplit(f"http://127.0.0.1:{server.server_port}/api/echo?test=1")
            self.assertTrue(warmup_request(endpoint, "preload-warmup"))
            self.assertEqual(received, [("/api/echo?test=1", "preload-warmup",
                                        {"marker": "preload-warmup", "message": "warmup"})])
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
