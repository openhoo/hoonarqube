#!/usr/bin/env python3
"""Capture real-project Sonar observations and replay the same native scope.

The manifest pins existing clean Git checkouts, source roots and exclusions.
Credentials are read from a protected file; no server is provisioned implicitly.
Differences are observations, never an automatic equivalence certification.
"""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error

from parity import read_secret_file, validate_search_page, write_json_atomic

SCANNER = ('sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1@'
           'sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalized_path(value):
    path = PurePosixPath(value.replace('\\', '/'))
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('finding path must stay inside project')
    return str(path)


def native_identities(report):
    if report.get('schema_version') != 1 or not isinstance(report.get('files'), list):
        raise ValueError('unsupported native report')
    project = report.get('project', {})
    if project.get('complete') is not True:
        raise ValueError('incomplete native analysis')
    result = Counter()
    for file in report['files']:
        for issue in file['issues']:
            span = issue['range']
            result[(issue['rule_key'], normalized_path(file['path']), span['start']['line'],
                    span['start']['column'], span['end']['line'],
                    span['end']['column'])] += 1
    return result


def sonar_identities(records, key):
    result = Counter()
    for issue in records:
        component = issue['component']
        if not component.startswith(key + ':'):
            raise ValueError('foreign Sonar component')
        span = issue.get('textRange')
        if span is None:
            # File-level observations remain distinct from fabricated ranges.
            position = (None, None, None, None)
        else:
            position = (span['startLine'], span['startOffset'],
                        span['endLine'], span['endOffset'])
        result[(issue['rule'], normalized_path(component[len(key) + 1:]), *position)] += 1
    return result


def comparison(native, reference):
    keys = sorted(set(native) | set(reference), key=repr)
    inventory = []
    for identity in keys:
        ours, theirs = native[identity], reference[identity]
        inventory.append({'identity': list(identity), 'native': ours,
                          'reference': theirs, 'matched': min(ours, theirs),
                          'native_only': max(0, ours - theirs),
                          'reference_only': max(0, theirs - ours)})
    return {'claim': 'observed_identity_differences', 'inventory': inventory,
            'native_total': sum(native.values()),
            'reference_total': sum(reference.values()),
            'matched': sum((native & reference).values()),
            'native_only': sum((native - reference).values()),
            'reference_only': sum((reference - native).values())}


def metric_comparison(native_metrics, reference_measures):
    reference = {measure['metric']: int(measure['value'])
                 for measure in reference_measures
                 if measure['metric'] in ('files', 'lines', 'ncloc', 'comment_lines')}
    mapping = {'files': 'files', 'lines': 'lines', 'ncloc': 'code_lines',
               'comment_lines': 'comment_lines'}
    return {key: {'native': native_metrics[mapping[key]], 'reference': value,
                  'matched': native_metrics[mapping[key]] == value}
            for key, value in reference.items()}


def file_metric_comparison(native_files, reference_files):
    native = {normalized_path(file['path']): file['metrics'] for file in native_files}
    reference = {normalized_path(file['path']): file['measures'] for file in reference_files}
    if len(native) != len(native_files) or len(reference) != len(reference_files):
        raise ValueError('duplicate file metric path')
    matched_cells = 0
    differences = []
    for path in sorted(native.keys() & reference.keys()):
        values = metric_comparison(native[path], reference[path])
        matched_cells += sum(value['matched'] for value in values.values())
        if any(not value['matched'] for value in values.values()):
            differences.append({'path': path, 'metrics': values})
    return {'matched_files': len(native.keys() & reference.keys()),
            'matched_cells': matched_cells, 'differences': differences,
            'native_only': sorted(native.keys() - reference.keys()),
            'reference_only': sorted(reference.keys() - native.keys())}


class Sonar:
    def __init__(self, url, token):
        self.url = url.rstrip('/')
        self.auth = 'Basic ' + base64.b64encode((token + ':').encode()).decode()

    def request(self, path, params=None, post=False):
        query = urllib.parse.urlencode(params or {})
        request = urllib.request.Request(
            self.url + path + ('' if post else '?' + query),
            data=query.encode() if post else None,
            headers={'Authorization': self.auth})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def pages(self, path, params, field, folder, label):
        records, seen = [], set()
        expected_total = expected_size = None
        for page in range(1, 1001):
            data = self.request(path, {**params, 'p': page, 'ps': 500})
            write_json_atomic(folder / f'{label}-page-{page}.json', data)
            items, total, size, done = validate_search_page(
                data, field, page, expected_total=expected_total,
                expected_page_size=expected_size, seen_keys=seen)
            expected_total, expected_size = total, size
            records.extend(items)
            if done:
                return records
        raise ValueError('pagination limit reached')


def run(command, folder, label, cwd, env=None):
    started = time.monotonic()
    timed_out = False
    try:
        process = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                 text=True, timeout=1800)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        def stream(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
        process = subprocess.CompletedProcess(command, None, stream(error.stdout),
                                              stream(error.stderr))
    (folder / f'{label}.stdout').write_text(process.stdout)
    (folder / f'{label}.stderr').write_text(process.stderr)
    write_json_atomic(folder / f'{label}-execution.json', {
        'argv': command, 'exit_code': process.returncode,
        'status': 'timed_out' if timed_out else 'completed',
        'seconds': time.monotonic() - started,
        'stdout_sha256': digest(folder / f'{label}.stdout'),
        'stderr_sha256': digest(folder / f'{label}.stderr')})
    if timed_out:
        raise RuntimeError(f'{label} timed out; see {folder}')
    if process.returncode:
        raise RuntimeError(f'{label} failed with exit {process.returncode}; see {folder}')
    return process.stdout


def verify_source(row):
    root = Path(row['path']).resolve()
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                     text=True).strip()
    if actual != row['commit']:
        raise ValueError(f"source commit mismatch: {row['name']}")
    dirty = subprocess.check_output(['git', 'status', '--porcelain',
                                    '--untracked-files=no'], cwd=root, text=True)
    if dirty:
        raise ValueError(f"tracked source modifications: {row['name']}")
    return root


def verify_reference_scope(row, folder):
    captured = json.loads((folder / 'source.json').read_text())
    for field in ('name', 'commit', 'project_key', 'sources', 'exclude', 'language'):
        default = [] if field == 'exclude' else None
        if captured.get(field, default) != row.get(field, default):
            raise ValueError(f'reference scope mismatch: {field}')


def verify_reference_files(root, folder):
    root = root.resolve()
    files = json.loads((folder / 'reference-source-files.json').read_text())
    for file in files:
        path = (root / file['path']).resolve()
        if not path.is_relative_to(root) or digest(path) != file['sha256']:
            raise ValueError('reference source content mismatch')


def execute(row, args, sonar, token):
    root = verify_source(row)
    folder = args.output / row['name']
    folder.mkdir(parents=True, exist_ok=True)
    key = row['project_key']
    if (folder / 'source.json').exists():
        verify_reference_scope(row, folder)
    elif args.native_only:
        raise ValueError('native replay requires a captured source manifest')
    if args.native_only:
        verify_reference_files(root, folder)
    else:
        write_json_atomic(folder / 'source.json', row)
        write_json_atomic(folder / 'server.json', sonar.request('/api/system/status'))
    if not args.native_only:
        try:
            sonar.request('/api/components/show', {'component': key})
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            sonar.request('/api/projects/create', {'project': key, 'name': key}, post=True)
        environment = {**os.environ, 'SONAR_TOKEN': token}
        command = ['docker', 'run', '--rm', '-e', 'SONAR_TOKEN',
                   '-e', 'SONAR_HOST_URL=' + args.scanner_url,
                   '-v', f'{root}:/usr/src:ro', SCANNER,
                   f'-Dsonar.projectKey={key}',
                   '-Dsonar.working.directory=/tmp/scanner-work',
                   '-Dsonar.scm.disabled=true',
                   '-Dsonar.cpd.exclusions=',
                   '-Dsonar.sources=' + ','.join(row['sources']),
                   '-Dsonar.exclusions=' + ','.join(row.get('exclude', []))]
        if row.get('language') == 'py':
            command.append('-Dsonar.python.version=3.13')
        scanner = run(command, folder, 'scanner', root, environment)
        # The scanner reports the task URL even with a read-only source mount.
        import re
        tasks = re.findall(r'api/ce/task\?id=([\w-]+)', scanner)
        if not tasks:
            raise ValueError('scanner did not provide a compute-engine task')
        deadline = time.monotonic() + 300
        while True:
            task = sonar.request('/api/ce/task', {'id': tasks[-1]})
            write_json_atomic(folder / 'compute-engine.json', task)
            status = task['task']['status']
            if status == 'SUCCESS':
                break
            if status in ('FAILED', 'CANCELED') or time.monotonic() >= deadline:
                raise RuntimeError(f'compute-engine status: {status}')
            time.sleep(2)
        issues = sonar.pages('/api/issues/search', {'componentKeys': key,
                             'resolved': 'false', 'additionalFields': '_all'},
                             'issues', folder, 'issues')
        hotspots = sonar.pages('/api/hotspots/search', {'projectKey': key},
                               'hotspots', folder, 'hotspots')
        write_json_atomic(folder / 'issues.json', issues)
        write_json_atomic(folder / 'hotspots.json', hotspots)
        profiles = sonar.request('/api/qualityprofiles/search', {'project': key})
        write_json_atomic(folder / 'profiles.json', profiles)
        for profile in profiles['profiles']:
            sonar.pages('/api/rules/search', {'qprofile': profile['key'],
                        'activation': 'true'}, 'rules', folder,
                        'active-' + profile['language'])
        measures = sonar.request('/api/measures/component', {'component': key,
                    'metricKeys': 'files,ncloc,lines,comment_lines,duplicated_lines,'
                                  'duplicated_blocks,duplicated_lines_density'})
        write_json_atomic(folder / 'measures.json', measures)
        file_measures = sonar.pages('/api/measures/component_tree',
                                    {'component': key, 'qualifiers': 'FIL',
                                     'metricKeys': 'lines,ncloc,comment_lines'},
                                    'components', folder, 'file-metrics')
        write_json_atomic(folder / 'file-metrics.json', file_measures)
        components = sonar.pages('/api/components/tree', {'component': key,
                                 'qualifiers': 'FIL'}, 'components', folder,
                                 'indexed-files')
        write_json_atomic(folder / 'indexed-files.json', components)
        reference_files = []
        for file in components:
            path = (root / file['path']).resolve()
            if not path.is_relative_to(root):
                raise ValueError('reference source path escapes pinned project')
            reference_files.append({'path': file['path'], 'sha256': digest(path)})
        write_json_atomic(folder / 'reference-source-files.json', reference_files)
    issues = json.loads((folder / 'issues.json').read_text())
    command = [str(args.binary), 'analyze', *row['sources'], '--format', 'json']
    for pattern in row.get('exclude', []):
        command.extend(['--exclude', pattern])
    native = json.loads(run(command, folder, args.label, root))
    write_json_atomic(folder / f'{args.label}.json', native)
    inventory = comparison(native_identities(native), sonar_identities(issues, key))
    measures = json.loads((folder / 'measures.json').read_text())
    inventory['metrics'] = metric_comparison(native['project']['metrics'],
                                             measures['component']['measures'])
    file_metrics_path = folder / 'file-metrics.json'
    if file_metrics_path.exists():
        inventory['file_metrics'] = file_metric_comparison(
            native['files'], json.loads(file_metrics_path.read_text()))
    indexed_path = folder / 'indexed-files.json'
    if indexed_path.exists():
        reference_paths = {normalized_path(file['path']) for file in json.loads(indexed_path.read_text())}
        native_paths = {normalized_path(file['path']) for file in native['files']}
        inventory['scope'] = {'matched': sorted(native_paths & reference_paths),
                              'native_only': sorted(native_paths - reference_paths),
                              'reference_only': sorted(reference_paths - native_paths)}
    source_files = []
    for file in native['files']:
        path = (root / file['path']).resolve()
        if not path.is_relative_to(root):
            raise ValueError('native source path escapes pinned project')
        source_files.append({'path': file['path'], 'sha256': digest(path)})
    verify_source(row)
    verify_reference_files(root, folder)
    write_json_atomic(folder / f'{args.label}-source-files.json', source_files)
    write_json_atomic(folder / f'{args.label}-comparison.json', inventory)
    return {field: inventory[field] for field in inventory if field != 'inventory'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--url', default='http://127.0.0.1:19000')
    parser.add_argument('--label', default='native')
    parser.add_argument('--scanner-url', default='http://host.docker.internal:19000')
    parser.add_argument('--native-only', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.binary = args.binary.resolve()
    token = ''
    sonar = None
    if not args.native_only:
        if args.token_file is None:
            parser.error('--token-file is required for a live scan')
        token = read_secret_file(args.token_file).strip()
        sonar = Sonar(args.url, token)
        server = sonar.request('/api/system/status')
        if server.get('status') != 'UP':
            raise RuntimeError('SonarQube is not UP')
        write_json_atomic(args.output / 'server.json', server)
    write_json_atomic(args.output / f'{args.label}-binary.json', {
        'path': str(args.binary), 'sha256': digest(args.binary)})
    summary = {}
    for row in json.loads(args.manifest.read_text()):
        try:
            summary[row['name']] = execute(row, args, sonar, token)
        except Exception as error:
            summary[row['name']] = {'status': 'failed', 'reason': str(error)}
        write_json_atomic(args.output / f'{args.label}-summary.json', summary)
        compact = dict(summary[row['name']])
        if 'scope' in compact:
            compact['scope'] = {key + '_files': len(paths)
                                for key, paths in compact['scope'].items()}
        print(row['name'], compact, flush=True)
    return int(any(row.get('status') == 'failed' for row in summary.values()))


if __name__ == '__main__':
    raise SystemExit(main())
