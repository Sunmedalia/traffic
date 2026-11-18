#!/usr/bin/env python3
"""Bind an isolated loopback HTTP(S) echo service for the impact runner."""
import argparse
import json
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Echo(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if self.path != '/api/echo' or not 0 < length <= 2 << 20:
            self.send_error(400)
            return
        body = self.rfile.read(length).decode()
        marker = self.headers.get('X-Traffic-Test-ID')
        if not marker or json.loads(body).get('marker') != marker:
            self.send_error(400)
            return
        response = json.dumps({'body': body}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port-file', required=True, type=Path)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error('--cert and --key must be supplied together')
    with ThreadingHTTPServer(('127.0.0.1', 0), Echo) as server:
        server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if args.cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert, args.key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        args.port_file.write_text(str(server.server_port), encoding='ascii')
        server.serve_forever()


if __name__ == '__main__':
    main()
