#!/usr/bin/env python3
"""HTTPS demo source. Runs only inside a throwaway 'source' network namespace."""
import http.server
import pathlib
import ssl
import sys

bind_ip, certificate, private_key, payload_path = sys.argv[1:]
payload = pathlib.Path(payload_path)

class Source(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/payload.bin':
            self.send_error(404)
            return
        contents = payload.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(contents)))
        self.end_headers()
        self.wfile.write(contents)
    def log_message(self, fmt, *args):
        print('HTTPS source: ' + (fmt % args), flush=True)

httpd = http.server.ThreadingHTTPServer((bind_ip, 443), Source)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(certificate, private_key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print('HTTPS source listening on ' + bind_ip + ':443', flush=True)
httpd.serve_forever()
