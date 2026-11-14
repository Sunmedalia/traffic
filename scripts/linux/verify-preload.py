#!/usr/bin/env python3
"""Exercise LD_PRELOAD capture with an isolated loopback HTTPS service.

Requires Python >=3.6, openssl, built traffic, and libtraffic-openssl.so.
Run as a capture-capable user. Creates a new output directory and stops its own
processes on completion. It does not change system service configuration.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time


def fixture(cert, key, port_file):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_args):
            pass

        def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-Length', '100')
            self.end_headers()

        def do_GET(self):
            if self.path.startswith('/passwd'):
                body = b'root:x:0:0:root:/root:/bin/bash\n'
            else:
                body = ('response:' + self.path).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Server(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = Server(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    Path(port_file).write_text(str(server.server_port))
    server.serve_forever()


def wait_for(check, processes, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError('child exited with status {}'.format(process.returncode))
        time.sleep(.05)
    raise RuntimeError('timed out waiting for test readiness')


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def verify(args):
    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    sock = str(root / 'plaintext.sock')
    if len(sock.encode()) >= 108:
        raise RuntimeError('output path too long for a Unix socket')
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.check_call(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                           '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    expected = {}
    service = collector = None
    service_log = (root / 'service.log').open('wb')
    collector_log = (root / 'collector.log').open('wb')
    started = time.time()
    try:
        env = os.environ.copy()
        env['LD_PRELOAD'] = str(Path(args.library).resolve())
        env['TRAFFIC_OPENSSL_SOCKET'] = sock
        service = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--fixture',
                                    str(cert), str(key), str(root / 'port')], env=env,
                                   stdout=service_log, stderr=service_log)
        wait_for(lambda: (root / 'port').exists(), [service])
        port = int((root / 'port').read_text())
        command = [str(Path(args.binary).resolve()), 'capture', '--interfaces', 'lo',
                   '--ports', str(port), '--openssl-preload-socket', sock,
                   '--output', str(root / 'session'), '--request-limit', '1048576',
                   '--response-limit', '1048576', '--trusted-proxies', '127.0.0.1']
        collector = subprocess.Popen(command, stdout=collector_log, stderr=collector_log)
        wait_for(lambda: Path(sock).is_socket(), [service, collector])
        context = ssl._create_unverified_context()  # isolated generated test certificate

        def connection():
            return http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=10)

        def request(conn, method, path, body=None, headers=None):
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            received = response.read()
            wanted = b'' if method == 'HEAD' else body if method == 'POST' else (
                b'root:x:0:0:root:/root:/bin/bash\n' if path.startswith('/passwd') else ('response:' + path).encode())
            if response.status != 200 or received != wanted:
                raise AssertionError('client response mismatch for ' + path)
            return dict(method=method, body=body or b'', response=wanted)

        conn = connection()
        for method, path, body, headers in [
            ('GET', '/plain', None, None),
            ('GET', '/search?q=union%20select%201', None, None),
            ('GET', '/passwd', None, None),
            ('GET', '/proxy', None, {'X-Forwarded-For': '198.51.100.7'}),
            ('HEAD', '/head', None, None),
            ('POST', '/unicode', '旧内核 HTTPS 正文'.encode(), None),
            ('POST', '/large', b'x' * (128 << 10), None),
        ]:
            expected[path] = request(conn, method, path, body, headers)
        conn.close()

        def parallel(index):
            client = connection()
            path = '/parallel/{}'.format(index)
            try:
                return path, request(client, 'GET', path)
            finally:
                client.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            expected.update(executor.map(parallel, range(12)))

        def records():
            output = subprocess.check_output([str(Path(args.analysis_binary).resolve()), 'requests',
                                              '--session', str(root / 'session'), '--limit', '1000'])
            return json.loads(output)

        def complete():
            captured = records()
            return len(captured) == len(expected) and all(record['status'] == 200 for record in captured)
        wait_for(complete, [service, collector])
        stop(collector)
        if collector.returncode != 0:
            raise RuntimeError('collector failed: {}'.format(collector.returncode))
        # After collector shutdown the application still serves requests. Sending
        # to a missing socket must leave application TLS behavior intact.
        client = connection()
        request(client, 'GET', '/after-collector-stop')
        client.close()
        records = [json.loads(subprocess.check_output([
            str(Path(args.analysis_binary).resolve()), 'show', record['id'],
            '--session', str(root / 'session')]))['transaction'] for record in records()]
        for record in records:
            case = expected[record['url']]
            if record['backend'] != 'openssl-preload' or record['incomplete'] or record['truncated']:
                raise AssertionError('capture state mismatch: ' + json.dumps(record))
            request_raw = base64.b64decode(record['request'])
            response_raw = base64.b64decode(record['response'])
            if request_raw.split(b'\r\n\r\n', 1)[1] != case['body']:
                raise AssertionError('request body mismatch for ' + record['url'])
            if response_raw.split(b'\r\n\r\n', 1)[1] != case['response']:
                raise AssertionError('response body mismatch for ' + record['url'])
        by_url = {record['url']: record for record in records}
        if 'SQLI-001' not in [a['rule'] for a in by_url['/search?q=union%20select%201']['alerts']]:
            raise AssertionError('SQLi rule missing')
        if 'RESPONSE-PASSWD-001' not in [a['rule'] for a in by_url['/passwd']['alerts']]:
            raise AssertionError('response rule missing')
        if by_url['/proxy']['client'] != '198.51.100.7:0' or not by_url['/proxy']['peer_client'].startswith('127.0.0.1:'):
            raise AssertionError('proxy attribution failed')
        status = json.loads((root / 'session' / 'status.json').read_text(encoding='utf-8'))
        if status['tls_dropped'] or status['queue_dropped'] or status['dropped']:
            raise AssertionError('observed loss: ' + json.dumps(status))
        evidence = root / 'passwd-evidence.zip'
        subprocess.check_call([str(Path(args.analysis_binary).resolve()), 'export', by_url['/passwd']['id'],
                               '--session', str(root / 'session'), '--out', str(evidence)])
        import zipfile
        with zipfile.ZipFile(str(evidence)) as archive:
            hashes = json.loads(archive.read('sha256.json'))
            for name, expected_hash in hashes.items():
                if hashlib.sha256(archive.read(name)).hexdigest() != expected_hash:
                    raise AssertionError('export hash mismatch for ' + name)
        report = dict(passed=True, kernel=os.uname().release, architecture=os.uname().machine,
                      python=sys.version, openssl=ssl.OPENSSL_VERSION, requests=len(expected),
                      status=status, elapsed_seconds=round(time.time()-started, 3),
                      collector_sha256=hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
                      library_sha256=hashlib.sha256(Path(args.library).read_bytes()).hexdigest(),
                      checks=['HTTP/1.1 TLS plaintext', 'keepalive', 'HEAD', 'Chinese body',
                              '128 KiB echo', 'concurrent connections', 'request and response alerts',
                              'trusted proxy', 'evidence ZIP SHA-256 verification', 'service continues after collector stops'])
        (root / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(report, ensure_ascii=True, indent=2))
    finally:
        stop(collector)
        stop(service)
        service_log.close()
        collector_log.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--fixture':
        fixture(*sys.argv[2:])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--binary', required=True)
        parser.add_argument('--library', required=True)
        parser.add_argument('--analysis-binary', required=True)
        parser.add_argument('--output', required=True)
        verify(parser.parse_args())
