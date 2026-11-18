"""Acceptance threshold boundaries must not silently treat missing metrics as zero."""
import base64
import sqlite3
import unittest
import json
import threading
import sys
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from impact import compare, warmup_request, external_load, capture_health, evidence_checks
from impact_load import LatencyHistogram
from impact_reconcile import reconcile


class ImpactChecks(unittest.TestCase):
    def setUp(self):
        self.baseline = dict(successful_rps=100, p99_ms=10,
                             target_cpu_one_core_percent=20, errors=0, requests=100,
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

    def test_error_threshold_is_a_rate(self):
        baseline = dict(self.baseline, errors=1)
        self.assertTrue(compare(dict(baseline, requests=200, errors=2), baseline)["checks"]["errors"])
        self.assertFalse(compare(dict(baseline, requests=99), baseline)["checks"]["errors"])
        self.assertFalse(compare(dict(baseline, requests=0), baseline)["checks"]["errors"])

    def test_reconcile_distinguishes_artifact_failures(self):
        def b64(data):
            return base64.b64encode(data).decode()

        def header(index):
            return f'x-Traffic-Test-Id: run-before-{index}\r\n'.encode()

        def transaction(index, *, paired=True, truncated=False, response_index=None):
            body = json.dumps({"marker": f"run-before-{index}", "message": "xxx"}).encode()
            if response_index is None:
                response_body = body
            else:
                response_body = body.replace(f"-{index}".encode(), f"-{response_index}".encode())
            echo = json.dumps({"body": response_body.decode()}).encode()
            return {"id": str(index), "backend": "openssl-preload", "truncated": truncated,
                    "request": b64(b"POST /api/echo HTTP/1.1\r\n" + header(index) + b"\r\n" + body),
                    "response": b64(b"HTTP/1.1 200 OK\r\n\r\n" + (echo[:-8] if truncated else echo))
                    if paired else "",
                    "status": 200 if paired else 0}

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = root / 'requests.jsonl'
            events = [{"id": f"run-before-{index}", "phase": "before", "sent": index != 0,
                       "success": index > 1} for index in range(8)]
            events.append({"id": "run-after-0", "phase": "after", "success": True})
            ledger.write_text(''.join(json.dumps(event) + '\n' for event in events))
            (root / 'tls').mkdir()
            chunks = [header(2)[:12], header(2)[12:], header(2), header(3), header(4),
                      header(5), header(7), header(99)]
            raw = [{"version": 1, "source": "source", "type": "source", "backend": "openssl-preload"}]
            raw.extend({"version": 1, "source": "source", "connection": "conn", "type": "data",
                        "direction": "read", "data": b64(chunk)} for chunk in chunks)
            (root / 'tls' / 'stream.jsonl').write_text(
                ''.join(json.dumps(event) + '\n' for event in raw) + '{"torn":')
            db = sqlite3.connect(root / 'analysis.sqlite')
            with db:
                db.execute('CREATE TABLE requests(data BLOB)')
                db.executemany('INSERT INTO requests VALUES (?)', [(json.dumps(row),) for row in [
                    transaction(2), transaction(2), transaction(3, paired=False),
                    transaction(4, truncated=True), transaction(7, response_index=3)]])
            db.close()
            with (root / 'reader.log').open('w') as log:
                report = reconcile(ledger, 0, {'before': 8, 'after': 1}, root, 'tls', 'run',
                                   3, root / 'joined.jsonl', log)
            self.assertTrue(report['raw_tls_partial_tail'])
            metrics = report['windows']['before']
            expected = {'not_dispatched': (1, 8), 'business_failed': (1, 7), 'raw_missing': (1, 6),
                        'reconstruction_missing': (2, 6), 'raw_seen_reconstruction_missing': (1, 5),
                        'raw_duplicate': (1, 5), 'offline_duplicate': (1, 4),
                        'unpaired': (2, 4), 'body_truncated': (1, 4), 'unexpected_raw': (1, 6)}
            for name, (count, denominator) in expected.items():
                self.assertEqual((metrics[name]['count'], metrics[name]['denominator']), (count, denominator), name)
                self.assertEqual(metrics[name]['ratio'], count / denominator, name)
            self.assertIsNone(report['windows']['after']['unpaired']['ratio'])
            checks = evidence_checks(report, ['before', 'after'], 'stop')
            self.assertFalse(checks['capture_reconciliation'])
            self.assertTrue(checks['post_exit_no_evidence'])

    def test_reconcile_rejects_duplicate_scheduled_id(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ledger = root / 'requests.jsonl'
            event = {"id": "run-load-0", "phase": "load", "success": True}
            ledger.write_text((json.dumps(event) + '\n') * 2)
            with self.assertRaises(sqlite3.IntegrityError):
                reconcile(ledger, 0, {'load': 2}, None, 'baseline', 'run', 3, root / 'joined.jsonl', None)

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
