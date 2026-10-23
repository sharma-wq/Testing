#!/usr/bin/env python3
"""Client for the isolated Linux-kernel acceptance lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
import socket

p = argparse.ArgumentParser()
p.add_argument('action', choices=['probe', 'fetch', 'deliver'])
p.add_argument('host')
p.add_argument('port', type=int)
p.add_argument('--stage')
a = p.parse_args()

if a.action == 'probe':
    try:
        with socket.create_connection((a.host, a.port), timeout=1.2):
            print(f'CONNECTED: {a.host}:{a.port}')
    except (OSError, TimeoutError) as exc:
        print(f'BLOCKED/FAILED: {a.host}:{a.port} ({type(exc).__name__})')
        raise SystemExit(1)
else:
    stage = Path(a.stage)
    if a.action == 'fetch':
        with urlopen(f'http://{a.host}:{a.port}/data', timeout=5) as resp:
            content = resp.read()
        digest = hashlib.sha256(content).hexdigest()
        tmp = stage / 'payload.partial'
        tmp.write_bytes(content)
        os.chmod(tmp, 0o644)
        tmp.replace(stage / 'payload.bin')
        (stage / 'manifest.sha256').write_text(digest + '\n')
        print('FETCHED into staging disk:', len(content), 'bytes; sha256:', digest)
    else:
        content = (stage / 'payload.bin').read_bytes()
        expected = (stage / 'manifest.sha256').read_text().strip()
        digest = hashlib.sha256(content).hexdigest()
        if digest != expected:
            raise SystemExit('FAULT: staging SHA-256 mismatch: no delivery permitted')
        req = Request(f'http://{a.host}:{a.port}/upload', content, method='POST')
        with urlopen(req, timeout=5) as resp:
            receipt = json.load(resp)
        if receipt['sha256'] != digest:
            raise SystemExit('FAULT: remote receiver SHA-256 mismatch')
        print('DELIVERED and VERIFIED by receiver:', receipt)
