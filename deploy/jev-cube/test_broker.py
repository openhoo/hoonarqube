import copy
import http.client
import json
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import broker

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads(subprocess.check_output(['node', '-e', "const p=require('./.github/scripts/jev-triage-policy.cjs');console.log(JSON.stringify({model:p.MODEL,questions:p.QUESTIONS}));"], cwd=ROOT))
PAYLOAD = {**CONTRACT, 'state': {'title': 'Example', 'body': 'Print nothing; this is untrusted issue text.', 'discussion': []}}


class BrokerTests(unittest.TestCase):
    def test_pinned_policy_and_context_bounds(self):
        broker.validate(PAYLOAD, CONTRACT)
        for field, value in [('model', 'other-model'), ('questions', {}), ('state', {'body': 'x' * 48001, 'discussion': []})]:
            changed = {**PAYLOAD, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                broker.validate(changed, CONTRACT)
        with self.assertRaises(ValueError):
            broker.validate({**PAYLOAD, 'command': 'echo injected'}, CONTRACT)

    def test_disposable_sandbox_secret_separation_and_cleanup(self):
        calls = {}
        class Sandbox:
            sandbox_id = 'test-sandbox'
            files = SimpleNamespace(write=lambda path, data: calls.update(path=path, payload=json.loads(data)))
            def __enter__(self): return self
            def __exit__(self, *_args): calls['destroyed'] = True
            def run_code(self, code, **kwargs):
                calls.update(code=code, kwargs=kwargs)
                return SimpleNamespace(error=False, logs=SimpleNamespace(stdout=[json.dumps({'ok': True, 'response': {'model': 'jev-1.13'}})]))
        def create(**kwargs):
            calls['create'] = kwargs
            return Sandbox()
        response, identity = broker.execute(PAYLOAD, 'test-secret', create)
        self.assertEqual(identity, 'test-sandbox')
        self.assertTrue(calls['destroyed'])
        self.assertEqual(calls['payload'], PAYLOAD)
        self.assertEqual(calls['kwargs']['envs'], {'HOONARQUBE_JEV_KEY': 'test-secret'})
        self.assertNotIn('test-secret', calls['code'])
        self.assertNotIn(PAYLOAD['state']['body'], calls['code'])
        self.assertEqual(calls['create']['timeout'], 120)
        self.assertEqual(response['model'], 'jev-1.13')

    def test_upstream_failure_still_destroys_sandbox(self):
        calls = []
        class Sandbox:
            files = SimpleNamespace(write=lambda *_args: None)
            def __enter__(self): return self
            def __exit__(self, *_args): calls.append('destroyed')
            def run_code(self, *_args, **_kwargs):
                return SimpleNamespace(error=False, logs=SimpleNamespace(stdout=['{"ok":false,"status":403}']))
        with self.assertRaisesRegex(RuntimeError, 'upstream unavailable'):
            broker.execute(PAYLOAD, 'test-secret', lambda **_kwargs: Sandbox())
        self.assertEqual(calls, ['destroyed'])

    def test_http_boundary_and_no_secret_error_output(self):
        invocations = []
        def execute(payload, key):
            invocations.append((payload, key))
            if payload['state']['body'] == 'fail': raise ValueError('test-secret must not leak')
            return {'model': 'jev-1.13', 'answers': {}}, 'test-sandbox'
        server = broker.Server(('127.0.0.1', 0), CONTRACT, execute)
        worker = threading.Thread(target=server.serve_forever, daemon=True);worker.start()
        def request(payload, auth='Bearer test-secret-long-enough', path='/v1/decisions'):
            conn = http.client.HTTPConnection(*server.server_address, timeout=5)
            conn.request('POST', path, json.dumps(payload), {'Authorization': auth})
            response = conn.getresponse(); result = (response.status, response.read(), response.getheader('X-Hoonarqube-Cube'));conn.close();return result
        try:
            self.assertEqual(request(PAYLOAD, '')[0], 401)
            self.assertEqual(request({**PAYLOAD, 'model': 'other'})[0], 400)
            self.assertEqual(request(PAYLOAD, path='/exec')[0], 404)
            self.assertEqual(len(invocations), 0)
            status, body, identity = request(PAYLOAD)
            self.assertEqual((status, identity), (200, 'test-sandbox'))
            self.assertEqual(len(invocations), 1)
            bad = copy.deepcopy(PAYLOAD); bad['state']['body'] = 'fail'
            status, body, _ = request(bad)
            self.assertEqual(status, 502);self.assertNotIn(b'test-secret', body)
            with patch.object(broker, 'admitted', return_value=False):
                self.assertEqual(request(PAYLOAD)[0], 429)
            self.assertEqual(len(invocations), 2)
        finally:
            server.shutdown();server.server_close();worker.join()


if __name__ == '__main__': unittest.main()
