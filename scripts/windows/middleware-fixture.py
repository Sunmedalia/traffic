"""Loopback-only HTTP/1.1 echo fixture for Windows middleware acceptance."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        data = "中间件采集验证\n".encode() + self.path.encode() + b"\n" + body
        if self.path.startswith("/large"):
            data += b"x" * (160 << 10)
        self.send_response(404 if self.path.startswith("/missing") else 200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        chunked = self.path.startswith("/chunked") and self.command != "HEAD"
        self.send_header("Transfer-Encoding" if chunked else "Content-Length", "chunked" if chunked else str(len(data)))
        self.end_headers()
        if self.command == "HEAD":
            return
        if chunked:
            for offset in range(0, len(data), 7):
                chunk = data[offset:offset + 7]
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.wfile.write(data)
        self.wfile.flush()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18090), Handler).serve_forever()
