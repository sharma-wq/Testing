#!/usr/bin/env python3
"""Small no-DNS HTTPS client and firewall socket probe for lab only."""
import hashlib
import http.client
import os
import socket
import ssl
import sys

operation = sys.argv[1]
if operation == 'probe':
    host, port = sys.argv[2], int(sys.argv[3])
    try:
        with socket.create_connection((host, port), timeout=2.0):
            print('CONNECTED:', host, port)
            raise SystemExit(0)
    except (socket.timeout, OSError) as exc:
        print('BLOCKED/FAILED: ' + type(exc).__name__ + ': ' + str(exc))
        raise SystemExit(2)

if operation == 'fetch':
    cert_path, target_file = sys.argv[2], sys.argv[3]
    ctx = ssl.create_default_context(cafile=cert_path)
    ctx.check_hostname = True
    with socket.create_connection(('10.11.0.10', 443), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname='diode.source.test') as tls:
            assert tls.version() in ('TLSv1.2', 'TLSv1.3'), tls.version()
            tls.sendall(b'GET /payload.bin HTTP/1.1\r\nHost: diode.source.test\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(tls)
            response.begin()
            if response.status != 200:
                raise RuntimeError('HTTPS source returned status ' + str(response.status))
            body = response.read()
            if len(body) != int(response.getheader('Content-Length', '-1')):
                raise RuntimeError('HTTPS content-length mismatch')
    with open(target_file, 'wb') as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    print('HTTPS VERIFIED: TLS + hostname + trusted certificate; bytes:', len(body))
    print('SHA256:', hashlib.sha256(body).hexdigest())
    raise SystemExit(0)
raise SystemExit('Usage: secure_client.py [probe HOST PORT | fetch CA_CERT STAGED_FILE]')
