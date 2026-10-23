#!/usr/bin/env python3
"""Tiny lab-only HTTP endpoint. Ports 443/22 are NOT TLS or SSH in this proof.
The test is strictly for network separation, nftables, and staged file transfer.
"""
import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('role', choices=['source', 'receiver'])
parser.add_argument('--host', required=True)
parser.add_argument('--port', required=True, type=int)
parser.add_argument('--file', required=True)
args = parser.parse_args()
path = Path(args.file)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if args.role != 'source' or self.path != '/data':
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if args.role != 'receiver' or self.path != '/upload':
            self.send_error(404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            self.send_error(400)
            return
        if not 0 < length < 10 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400)
            return
        path.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        payload = json.dumps({'sha256': digest, 'bytes': len(body)}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *values):
        print(f'{args.role}:{args.port}: ' + fmt % values, flush=True)

ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
