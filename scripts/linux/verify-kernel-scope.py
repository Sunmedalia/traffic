#!/usr/bin/env python3
"""Exercise BPF PID/start-time and port scope directly, without collector filters.

Runs isolated loopback HTTPS fixtures and reads raw eCaptureQ protobuf messages.
Requires Linux/root, Python >=3.6, openssl and the bundled scoped eCapture.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time


def fixture(cert, key, ready, host, first_port):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_args):
            pass

        def do_GET(self):
            body = self.path.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Server(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    servers = [Server((host, first_port), Handler), Server((host, 0), Handler)]
    for server in servers:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    Path(ready).write_text(json.dumps([server.server_port for server in servers]))
    threading.Event().wait()


def fields(data):
    def varint(position):
        value = 0
        for shift in range(0, 70, 7):
            if position >= len(data):
                raise ValueError('truncated protobuf')
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, position
        raise ValueError('invalid protobuf varint')
    result, position = {}, 0
    while position < len(data):
        tag, position = varint(position)
        number, wire = tag >> 3, tag & 7
        if wire == 0:
            result[number], position = varint(position)
        elif wire == 2:
            length, position = varint(position)
            if position + length > len(data):
                raise ValueError('truncated protobuf bytes')
            result[number] = data[position:position + length]
            position += length
        elif wire in (1, 5):
            position += 8 if wire == 1 else 4
        else:
            raise ValueError('unsupported protobuf wire type')
    return result


class RawWebSocket:
    def __init__(self, port):
        self.socket = socket.create_connection(('127.0.0.1', port), timeout=1)
        self.socket.settimeout(1)
        key = base64.b64encode(os.urandom(16)).decode()
        request = ('GET / HTTP/1.1\r\nHost: 127.0.0.1:{0}\r\nUpgrade: websocket\r\n'
                   'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                   'Sec-WebSocket-Key: {1}\r\nOrigin: http://127.0.0.1:{0}\r\n\r\n').format(port, key)
        self.socket.sendall(request.encode())
        # Read only through the HTTP header, preserving any immediate frames.
        header = bytearray()
        while not header.endswith(b'\r\n\r\n'):
            header.extend(self.read(1))
            if len(header) > 8192:
                raise ValueError('oversized WebSocket upgrade header')
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).lower()
        if not bytes(header).startswith(b'HTTP/1.1 101 ') or accept not in bytes(header).lower():
            raise ValueError('WebSocket upgrade failed')

    def read(self, length):
        data = bytearray()
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise EOFError('probe WebSocket closed')
            data.extend(chunk)
        return bytes(data)

    def message(self):
        header = self.read(2)
        opcode, length = header[0] & 15, header[1] & 127
        if not header[0] & 128:
            raise ValueError('fragmented frame unsupported in this test')
        if length == 126:
            length = struct.unpack('!H', self.read(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', self.read(8))[0]
        if length > 2 << 20:
            raise ValueError('oversized probe message')
        mask = self.read(4) if header[1] & 128 else None
        data = self.read(length)
        if mask:
            data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
        if opcode == 8:
            raise EOFError('probe closed connection')
        if opcode not in (1, 2):
            raise ValueError('unexpected WebSocket control frame')
        return data

    def close(self):
        self.socket.close()


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError('test process exceeded stop budget')


def wait_ports(path, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            if process.poll() is not None:
                raise RuntimeError('fixture failed')
            time.sleep(.05)
    raise RuntimeError('fixture readiness timed out')


def verify(args):
    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.check_call(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                           '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes, logs, connection = [], [], None
    captured, controls = [], []
    try:
        for index, host in enumerate(['127.0.0.1', '127.0.0.2']):
            ready = root / ('ports-' + str(index))
            log = (root / ('fixture-' + str(index) + '.log')).open('wb')
            logs.append(log)
            port = 0 if index == 0 else ports[0][0]
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--fixture',
                                        str(cert), str(key), str(ready), host, str(port)], stdout=log, stderr=log)
            processes.append(process)
            if index == 0:
                ports = []
            ports.append(wait_ports(ready, process))
        target, other = processes
        stat = Path('/proc/{}/stat'.format(target.pid)).read_text().rsplit(')', 1)[1].split()
        ticks = int(stat[19])
        library = next(line.split()[5] for line in Path('/proc/{}/maps'.format(target.pid)).read_text().splitlines()
                       if '/libssl.so.' in line and len(line.split()) >= 6)
        scope = root / 'scope.json'

        def update(revision, started, allowed_ports):
            temporary = root / 'scope.tmp'
            temporary.write_text(json.dumps({'schema_version': 1, 'revision': revision,
                                             'pids': [{'pid': target.pid, 'start_ticks': started}],
                                             'ports': allowed_ports}))
            temporary.replace(scope)
        update(1, ticks, [ports[0][0]])
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        websocket_port = listener.getsockname()[1]
        listener.close()
        log = (root / 'probe.log').open('wb')
        logs.append(log)
        probe = subprocess.Popen([str(Path(args.ecapture).resolve()), 'tls', '--libssl', library,
                                  '--traffic-scope-file', str(scope), '--eventaddr', '/dev/null',
                                  '--mapsize', '1024', '--perf-reorder', '--perf-reorder-lag-ms', '100',
                                  '--ecaptureq', 'ws://127.0.0.1:{}/'.format(websocket_port)], stdout=log, stderr=log)
        processes.append(probe)
        deadline = time.monotonic() + 15
        while connection is None and time.monotonic() < deadline:
            try:
                connection = RawWebSocket(websocket_port)
            except OSError:
                if probe.poll() is not None:
                    raise RuntimeError('probe failed to start')
                time.sleep(.05)
        if connection is None:
            raise RuntimeError('probe WebSocket unavailable')

        def receive():
            entry = fields(connection.message())
            if entry.get(1) == 1:
                controls.append(entry.get(4, b'').decode(errors='replace'))
            if entry.get(1) == 2 and 2 in entry:
                event = fields(entry[2])
                captured.append({'pid': event.get(7), 'stream': event.get(16, b'').decode(),
                                 'payload': event.get(11, b''), 'sequence': event.get(17)})

        def until(check, seconds=10):
            end = time.monotonic() + seconds
            while not check():
                if time.monotonic() > end:
                    raise RuntimeError('expected probe control/event not received')
                try:
                    receive()
                except socket.timeout:
                    pass

        def request(host, port, marker):
            client = http.client.HTTPSConnection(host, port, timeout=5, context=ssl._create_unverified_context())
            try:
                client.request('GET', '/' + marker)
                response = client.getresponse()
                assert response.status == 200 and response.read() == ('/' + marker).encode()
            finally:
                client.close()

        def seen(marker):
            return any(marker.encode() in event['payload'] for event in captured)

        until(lambda: 'traffic-control-v1:ready' in controls)
        request('127.0.0.1', ports[0][0], 'scope-positive-initial')
        until(lambda: seen('scope-positive-initial'))
        assert any(event['stream'].startswith('{}:{}/'.format(target.pid, ticks)) for event in captured)
        request('127.0.0.2', ports[1][0], 'scope-rejected-pid')
        request('127.0.0.1', ports[0][1], 'scope-rejected-port')
        update(2, ticks + 1, [ports[0][0]])
        until(lambda: 'traffic-control-v1:scope-applied:2' in controls)
        request('127.0.0.1', ports[0][0], 'scope-rejected-start')
        update(3, ticks, [ports[0][1]])
        until(lambda: 'traffic-control-v1:scope-applied:3' in controls)
        request('127.0.0.1', ports[0][1], 'scope-positive-updated')
        until(lambda: seen('scope-positive-updated'))
        request('127.0.0.1', ports[0][0], 'scope-rejected-old-port')
        empty = root / 'scope.tmp'
        empty.write_text(json.dumps({'schema_version': 1, 'revision': 4, 'pids': [], 'ports': [ports[0][1]]}))
        empty.replace(scope)
        until(lambda: 'traffic-control-v1:scope-applied:4' in controls)
        request('127.0.0.1', ports[0][1], 'scope-rejected-empty')
        empty.write_text('{invalid-json')
        empty.replace(scope)
        until(lambda: 'traffic-control-v1:scope-error' in controls)
        request('127.0.0.1', ports[0][1], 'scope-rejected-invalid')
        update(5, ticks, [ports[0][0]])
        until(lambda: 'traffic-control-v1:scope-applied:5' in controls)
        request('127.0.0.1', ports[0][0], 'scope-positive-recovered')
        until(lambda: seen('scope-positive-recovered'))
        # Wait through idle perf flush and transport delivery before asserting absence.
        end = time.monotonic() + .5
        while time.monotonic() < end:
            try:
                receive()
            except socket.timeout:
                pass
        rejected = ['scope-rejected-pid', 'scope-rejected-port', 'scope-rejected-start', 'scope-rejected-old-port',
                    'scope-rejected-empty', 'scope-rejected-invalid']
        assert not any(seen(marker) for marker in rejected), 'excluded plaintext reached raw eCaptureQ output'
        assert all(event['pid'] == target.pid for event in captured), 'unselected PID reached transport'
        stop(probe)
        assert probe.returncode == 0, 'probe did not stop cleanly; inspect probe.log'
        request('127.0.0.1', ports[0][0], 'scope-service-after-stop')
        report = {'passed': True, 'target_pid': target.pid, 'start_ticks': ticks,
                  'excluded_pid': other.pid, 'events': len(captured), 'rejected_markers': rejected,
                  'checks': ['raw eCaptureQ without collector filtering', 'host PID allowlist',
                             'kernel process start identity', 'port allowlist', 'dynamic port replacement',
                             'empty allowlist denies all', 'invalid update denies all', 'valid update recovery',
                             'service continues after probe stops']}
        (root / 'report.json').write_text(json.dumps(report, indent=2))
        (root / 'events.jsonl').write_text(''.join(json.dumps(dict(event, payload=base64.b64encode(event['payload']).decode())) + '\n' for event in captured))
        print(json.dumps(report, indent=2))
    finally:
        if connection is not None:
            connection.close()
        for process in reversed(processes):
            stop(process)
        for log in logs:
            log.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--fixture':
        fixture(*sys.argv[2:6], int(sys.argv[6]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--ecapture', required=True)
        parser.add_argument('--output', required=True)
        verify(parser.parse_args())
