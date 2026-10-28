#!/usr/bin/env python3
"""Tiny fake of the Apify API over TLS 1.3, for debugging the HolyC TLS/HTTP/client code offline.
Runs inside the lab container (127.0.0.1:8443). Writes TLS secrets to /out/keys.log so the
captured net.pcap can be decrypted with: tshark -r net.pcap -o tls.keylog_file:keys.log -V"""
import json, ssl, subprocess, sys, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("MOCK_TOKEN", "test-token")
PLAIN = "--plain" in sys.argv  # plain HTTP on :8080 for the HTTP client before TLS exists

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a):
        sys.stderr.write("mock: " + fmt % a + "\n")
    def _send(self, code, body, chunked=False, ctype="application/json"):
        data = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
            for i in range(0, len(data), 37):
                c = data[i:i + 37]; self.wfile.write(b"%x\r\n%s\r\n" % (len(c), c))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def _auth(self):
        ok = self.headers.get("Authorization") == "Bearer " + TOKEN
        if not ok:
            self._send(401, {"error": {"type": "token-not-provided", "message": "mock: bad token"}})
        return ok
    def do_GET(self):
        if self.path.startswith("/v2/users/me"):
            if self._auth():
                self._send(200, {"data": {"id": "mockUser", "username": "mock-user", "plan": {"id": "FREE"}}})
        elif self.path.startswith("/big"):
            self._send(200, [{"i": i, "text": "line %d é \"quoted\"" % i} for i in range(300)], chunked=True)
        elif self.path.startswith("/v2/datasets/"):
            if self._auth():
                self._send(200, [{"url": "https://example.com", "title": "Example Domain"}], chunked=True)
        else:
            self._send(404, {"error": {"type": "record-not-found"}})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if "/run-sync-get-dataset-items" in self.path:
            if not self._auth():
                return
            if self.path.startswith("/v2/acts/test~delayed-run/"):
                time.sleep(0.5)
            sys.stderr.write("mock: run input = %s\n" % body.decode())
            self._send(201, [{"url": "https://example.com", "title": "Example Domain", "text": "mock result"},
                             {"url": "https://example.org", "title": "Example Org", "text": "second ✓"}], chunked=True)
        elif "/runs" in self.path or self.path.startswith("/v2/acts/"):
            if self._auth():
                self._send(201, {"data": {"id": "mockRun1", "status": "READY", "defaultDatasetId": "mockDs1"}})
        else:
            self._send(404, {"error": {"type": "record-not-found"}})

if PLAIN:
    ThreadingHTTPServer(("127.0.0.1", 8080), H).serve_forever()
else:
    d = "/tmp/tos"; os.makedirs(d, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d + "/k.pem",
                    "-out", d + "/c.pem", "-days", "2", "-subj", "/CN=api.apify.com"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(d + "/c.pem", d + "/k.pem")
    ctx.set_ecdh_curve("X25519")
    ctx.keylog_filename = "/out/keys.log"
    s = ThreadingHTTPServer(("127.0.0.1", 8443), H)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    s.serve_forever()
