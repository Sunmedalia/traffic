#!/usr/bin/env python3
"""HTTP/1 load worker: read one JSON config from stdin, stream a JSONL ledger.

Can run through an SSH command so HTTP generation runs on a separate machine.
Only the final result and request metadata cross back to the impact controller.
"""
import concurrent.futures
import hashlib
import http.client
import json
import math
import platform
import ssl
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


class LatencyHistogram:
    """Bounded logarithmic histogram; reported quantiles are upper bounds.

    Bucket error is at most 0.1% plus one microsecond. Memory depends on the
    range of observed latency, rather than the number of requests in an 8h run.
    """
    step = math.log1p(0.001)

    def __init__(self):
        self.buckets = {}
        self.count = 0

    def add(self, milliseconds):
        bucket = math.ceil(math.log1p(milliseconds * 1000) / self.step)
        self.buckets[bucket] = self.buckets.get(bucket, 0) + 1
        self.count += 1

    def quantile(self, fraction):
        if not self.count:
            raise ValueError('no completed requests')
        rank = int((self.count - 1) * fraction)
        for bucket, count in sorted(self.buckets.items()):
            rank -= count
            if rank < 0:
                return math.expm1(bucket * self.step) / 1000
        raise AssertionError('histogram count mismatch')


def run_load(config, record):
    endpoint = urlsplit(config['url'])
    rate, seconds = float(config['rate']), float(config['seconds'])
    concurrency, body_bytes = int(config['concurrency']), int(config['body_bytes'])
    if (endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username
            or endpoint.fragment or not math.isfinite(rate) or not math.isfinite(seconds)
            or min(rate, seconds, concurrency) <= 0 or not 0 <= body_bytes <= 1 << 20):
        raise ValueError('invalid worker configuration')
    prefix, phase = config['run_id'], config['phase']
    local = threading.local()
    connections, connections_lock = set(), threading.Lock()
    path = (endpoint.path or '/') + ('?' + endpoint.query if endpoint.query else '')

    def request(index):
        marker = '{}-{}-{}'.format(prefix, phase, index)
        body = json.dumps({'marker': marker, 'message': 'x' * body_bytes})
        entered, sent_at = time.monotonic(), time.time()
        good, error = False, ''
        conn = getattr(local, 'connection', None)
        try:
            if conn is None:
                if endpoint.scheme == 'https':
                    conn = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, timeout=5,
                                                       context=ssl._create_unverified_context())
                else:
                    conn = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
                local.connection = conn
                with connections_lock:
                    connections.add(conn)
            conn.request('POST', path, body.encode(), {'Content-Type': 'application/json',
                                                      'X-Traffic-Test-ID': marker})
            response = conn.getresponse()
            data = response.read((2 << 20) + 1)
            decoded = json.loads(data) if response.status == 200 and len(data) <= 2 << 20 else None
            good = isinstance(decoded, dict) and decoded.get('body') == body
            if not good:
                error = 'invalid_echo_response'
        except (OSError, ValueError, KeyError, http.client.HTTPException) as failure:
            error = type(failure).__name__
            if conn is not None:
                conn.close()
                with connections_lock:
                    connections.discard(conn)
            local.connection = None
        elapsed = time.monotonic() - entered
        return elapsed, good, {'id': marker, 'phase': phase, 'sent_at_unix': sent_at,
                               'elapsed_ms': elapsed * 1000, 'sent': True, 'success': good, 'error': error}

    histogram, errors, dropped, pending = LatencyHistogram(), 0, 0, set()

    def finish(future):
        nonlocal errors
        elapsed, good, event = future.result()
        histogram.add(elapsed * 1000)
        errors += not good
        record(event)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            start = time.monotonic()
            total = math.ceil(rate * seconds)
            for index in range(total):
                delay = start + index / rate - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                done = {future for future in pending if future.done()}
                for future in done:
                    finish(future)
                pending -= done
                if len(pending) >= concurrency * 2:
                    dropped += 1
                    record({'id': '{}-{}-{}'.format(prefix, phase, index), 'phase': phase,
                            'sent': False, 'success': False, 'error': 'generator_capacity'})
                    continue
                pending.add(pool.submit(request, index))
            for future in concurrent.futures.as_completed(pending):
                finish(future)
            duration = time.monotonic() - start
    finally:
        for conn in connections:
            conn.close()
    return {'requests': histogram.count, 'errors': errors, 'generator_dropped': dropped,
            'successful_rps': (histogram.count - errors) / duration,
            'p95_ms': histogram.quantile(.95) if histogram.count else None,
            'p99_ms': histogram.quantile(.99) if histogram.count else None,
            'latency_quantile_error': 'upper bound; <=0.1% plus 1us',
            'load_duration_seconds': duration}


def main():
    config = json.loads(sys.stdin.readline(1 << 20))

    def emit(event):
        sys.stdout.write(json.dumps(dict(event, kind='request')) + '\n')
    result = run_load(config, emit)
    result['worker'] = {'platform': platform.platform(), 'python': platform.python_version(),
                        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    sys.stdout.write(json.dumps(dict(result, kind='result')) + '\n')
    sys.stdout.flush()


if __name__ == '__main__':
    main()
