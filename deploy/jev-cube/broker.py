#!/usr/bin/env python3
"""Fixed Jev request execution in disposable HooCube sandboxes; no GitHub access."""
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_INPUT = 65536
MAX_OUTPUT = 131072
SLOTS = threading.BoundedSemaphore(2)
RECENT = deque()
RATE_LOCK = threading.Lock()

# This source is constant. Report text and credentials never become Python code.
GUEST = '''import os,json,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
try:
 opener=urllib.request.build_opener(NoRedirect())
 request=urllib.request.Request('https://ai.openhoo.ai/v1/decisions',data=open('/tmp/request.json','rb').read(),headers={'Authorization':'Bearer '+os.environ['HOONARQUBE_JEV_KEY'],'Content-Type':'application/json','User-Agent':'Hoonarqube-Jev-Triage/1.0 (+https://github.com/openhoo/hoonarqube)'})
 with opener.open(request,timeout=45) as response:
  raw=response.read(131073)
  if len(raw)>131072: raise ValueError('size')
  value=json.loads(raw)
  print(json.dumps({'ok':True,'response':value},separators=(',',':')))
except urllib.error.HTTPError as error:
 print(json.dumps({'ok':False,'status':error.code,'challenge':error.headers.get('cf-mitigated')=='challenge'}))
except Exception:
 print(json.dumps({'ok':False,'error':'upstream-unavailable'}))
'''


def validate(payload, contract):
    if not isinstance(payload, dict) or set(payload) != {'model', 'state', 'questions'}:
        raise ValueError('request shape')
    if payload['model'] != contract['model'] or payload['questions'] != contract['questions']:
        raise ValueError('fixed policy mismatch')
    state = payload['state']
    if not isinstance(state, dict) or set(state) - {'title', 'body', 'author', 'discussion'}:
        raise ValueError('state shape')
    if any(not isinstance(state.get(k, ''), str) for k in ('title', 'body', 'author')):
        raise ValueError('state fields')
    if not isinstance(state.get('discussion'), list):
        raise ValueError('discussion')
    for comment in state['discussion']:
        if not isinstance(comment, dict) or set(comment) - {'id', 'author', 'body'}:
            raise ValueError('comment shape')
        if not isinstance(comment.get('body', ''), str) or not isinstance(comment.get('author', ''), str):
            raise ValueError('comment fields')
    if len(json.dumps(state, ensure_ascii=False, separators=(',', ':')).encode()) > 48000:
        raise ValueError('context size')


def execute(payload, key, sandbox_factory=None):
    if sandbox_factory is None:
        from e2b_code_interpreter import Sandbox
        sandbox_factory = Sandbox.create
    with sandbox_factory(template='drachen-development', timeout=120,
                         metadata={'purpose': 'hoonarqube-jev-triage'}) as sandbox:
        sandbox.files.write('/tmp/request.json', json.dumps(payload, ensure_ascii=False))
        result = sandbox.run_code(GUEST, envs={'HOONARQUBE_JEV_KEY': key}, timeout=65)
        if result.error:
            raise RuntimeError('sandbox execution failed')
        output = ''.join(result.logs.stdout)
        if len(output.encode()) > MAX_OUTPUT + 1024:
            raise RuntimeError('sandbox output too large')
        envelope = json.loads(output)
        if envelope.get('ok') is not True:
            # Never forward provider text, exceptions, or headers to the caller.
            raise RuntimeError('upstream unavailable')
        response = envelope.get('response')
        if not isinstance(response, dict) or len(json.dumps(response).encode()) > MAX_OUTPUT:
            raise RuntimeError('invalid response')
        return response, sandbox.sandbox_id


def admitted():
    now = time.monotonic()
    with RATE_LOCK:
        while RECENT and RECENT[0] <= now - 60:
            RECENT.popleft()
        if len(RECENT) >= 10:
            return False
        RECENT.append(now)
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = 'HoonarqubeCube/1'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass

    def reply(self, status, body, sandbox_id=None):
        raw = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        if sandbox_id:
            self.send_header('X-Hoonarqube-Cube', sandbox_id)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path != '/health':
            self.reply(404, {'error': 'not-found'})
            return
        self.reply(200, {'status': 'ready', 'model': self.server.contract['model'],
                         'contract_sha256': self.server.contract_hash})

    def do_POST(self):
        if self.path != '/v1/decisions':
            self.reply(404, {'error': 'not-found'})
            return
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer ') or not 20 <= len(auth[7:]) <= 4096 or any(c.isspace() for c in auth[7:]):
            self.reply(401, {'error': 'missing-key'})
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= MAX_INPUT or self.headers.get('Transfer-Encoding'):
                raise ValueError('size')
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('truncated')
            payload = json.loads(raw)
            validate(payload, self.server.contract)
        except (ValueError, OSError):
            self.reply(400, {'error': 'invalid-request'})
            return
        if not SLOTS.acquire(blocking=False):
            self.reply(429, {'error': 'busy'})
            return
        try:
            if not admitted():
                self.reply(429, {'error': 'rate-limit'})
                return
            response, sandbox_id = self.server.executor(payload, auth[7:])
            self.reply(200, response, sandbox_id)
            print(json.dumps({'event': 'completed', 'sandbox_id': sandbox_id,
                              'input_sha256': hashlib.sha256(raw).hexdigest()}), flush=True)
        except Exception:
            self.reply(502, {'error': 'cube-evaluation-failed'})
            print(json.dumps({'event': 'evaluation-failed'}), flush=True)
        finally:
            SLOTS.release()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def handle_error(self, *_args):
        print(json.dumps({'event': 'request-failed'}), flush=True)

    def __init__(self, address, contract, executor=execute):
        self.contract = contract
        self.contract_hash = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.executor = executor
        super().__init__(address, Handler)


def main():
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
    os.environ['E2B_API_KEY'] = (credentials / 'cube-api-key').read_text().strip()
    os.environ['E2B_API_URL'] = 'http://127.0.0.1:3000'
    os.environ['SSL_CERT_FILE'] = '/etc/hoonarqube-jev-cube/cube-ca.pem'
    contract = json.loads((Path(__file__).parent / 'contract.json').read_text())
    Server(('100.114.173.91', 9138), contract).serve_forever()


if __name__ == '__main__':
    main()
