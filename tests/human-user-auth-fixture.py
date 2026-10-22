#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Enroll/verify an existing disposable bootstrap fixture; never register users."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import sys
import time
import urllib.request
import urllib.parse

base, token_name, subject, seed_name = sys.argv[1:5]
tenant = sys.argv[5] if len(sys.argv) > 5 else '__wr_default'
token_path = Path(token_name)
seed_path = Path(seed_name)
query = '?tenant=__wr_default&guard_timestamp=123&guard_loc_class=public&guard_risk=0'

def post(path, body=None, bearer=None):
    headers = {'Content-Type': 'application/json'}
    if bearer:
        headers['Authorization'] = 'Bearer ' + bearer
    request = urllib.request.Request(base + path,
        data=json.dumps(body or {}).encode(), headers=headers, method='POST')
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)

def code(secret, step):
    digest = hmac.new(secret, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}'

if seed_path.exists():
    material = json.loads(seed_path.read_text(encoding='utf-8'))
else:
    bearer = token_path.read_text(encoding='utf-8').strip()
    challenge = post('/auth/mfa/enroll/start' + query, {'subject': subject}, bearer)
    material = {'secret': challenge['secret_base32'], 'step': int(time.time()) // 30}
    secret = base64.b32decode(material['secret'])
    post('/auth/mfa/enroll/confirm' + query,
         {'challenge': challenge['challenge'], 'code': code(secret, material['step'])}, bearer)
secret = base64.b32decode(material['secret'])
step = max(int(time.time()) // 30, material['step'] + 1)
while step > int(time.time()) // 30 + 1:
    time.sleep(0.05)
login = post('/auth/login?' + urllib.parse.urlencode({'username': subject, 'tenant': tenant}))
verified = post('/auth/mfa/verify', {'session_token': login['session_token'], 'code': code(secret, step)})
material['step'] = step
seed_path.write_text(json.dumps(material), encoding='utf-8')
os.chmod(seed_path, 0o600)
token_path.write_text(verified['access_token'] + '\n', encoding='utf-8')
os.chmod(token_path, 0o600)
