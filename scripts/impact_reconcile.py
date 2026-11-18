"""Join the synthetic load ledger, raw request headers and the offline index."""
import base64
import http.client
import io
import json
import re
import sqlite3
import subprocess
import tempfile
from collections import Counter
from contextlib import closing
from pathlib import Path


HEADER = rb'^(?i:X-Traffic-Test-ID):[ \t]*'
CHUNKED = re.compile(rb'^Transfer-Encoding:[ \t]*chunked[ \t]*\r?$', re.IGNORECASE | re.MULTILINE)


def line_tail(data):
    tail = data.rsplit(b'\n', 1)[-1]
    return tail if len(tail) <= 512 else b'\0'


def scan_stream(chunks, pattern):
    """Match complete ID header lines across reads, never across stream gaps."""
    tail = b''
    for chunk in chunks:
        data = tail + chunk
        boundary = data.rfind(b'\n') + 1
        if boundary:
            for match in pattern.finditer(data, 0, boundary):
                yield match[1].decode('ascii')
        tail = line_tail(data[boundary:])


def raw_tls_ids(path, pattern, diagnostics):
    tails, backends = {}, {}
    with path.open('rb') as stream:
        for line in stream:
            if not line.endswith(b'\n'):
                diagnostics['raw_tls_partial_tail'] = True
                break
            event = json.loads(line)
            if event['version'] != 1:
                raise ValueError('unsupported raw TLS event version')
            source = event['source']
            connection = event.get('connection', '')
            kind = event['type']
            if kind == 'source':
                backends[source] = event['backend']
            elif kind == 'iis':
                iis = event['iis']
                if iis['type'] == 'request':
                    for name, value in iis.get('headers') or []:
                        field = f'{name}: {value}'.encode('utf-8')
                        match = pattern.fullmatch(field)
                        if match:
                            yield match[1].decode('ascii'), backends[source]
            elif kind == 'data':
                key = source, connection, event['direction']
                data = base64.b64decode(event.get('data', ''), validate=True)
                tail = tails.pop(key, b'')
                for marker in scan_stream((tail, data), pattern):
                    yield marker, backends[source]
                if not event.get('incomplete') and event.get('original_length', 0) <= len(data):
                    tails[key] = line_tail(tail + data)
            elif kind in ('close', 'end', 'loss'):
                if kind == 'end':
                    backends.pop(source, None)
                for key in list(tails):
                    if key[0] == source and (kind != 'close' or key[1] == connection):
                        del tails[key]


def raw_packet_ids(session, pattern, work, log):
    groups = {}
    for path in sorted([*session.glob('packets-*.pcap'), *(session / 'packets').glob('*.pcap')]):
        groups.setdefault((path.parent, path.stem.rsplit('-', 1)[0]), []).append(path)
    for number, paths in enumerate(groups.values()):
        directory = work / str(number)
        directory.mkdir()
        # Stitch rotations in recorder order. Analyze each interface separately
        # so that observations duplicated across interfaces remain visible.
        if len(paths) > 1:
            source = directory / 'combined.pcap'
            subprocess.run(['mergecap', '-a', '-F', 'pcap', '-w', str(source), *map(str, paths)],
                           stdout=log, stderr=log, check=True)
        else:
            source = paths[0]
        flows = directory / 'flows'
        flows.mkdir()
        subprocess.run(['tcpflow', '-r', str(source), '-o', str(flows), '-X', str(directory / 'report.xml'),
                        '-E', 'tcpdemux'], stdout=log, stderr=log, check=True)
        for path in flows.iterdir():
            if path.is_file():
                with path.open('rb') as flow:
                    for marker in scan_stream(iter(lambda: flow.read(65536), b''), pattern):
                        yield marker, 'pcap'


def offline_rows(session):
    pointer = session / 'analysis-current.json'
    name = json.loads(pointer.read_text(encoding='utf-8'))['file'] if pointer.exists() else 'analysis.sqlite'
    if name != 'analysis.sqlite' and not re.fullmatch(r'analysis-[0-9a-f]{32}\.sqlite', name):
        raise ValueError('invalid analysis database name')
    with closing(sqlite3.connect((session / name).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        for (data,) in db.execute('SELECT data FROM requests'):
            yield json.loads(data)


def http_message(data, *, response=False, truncated=False):
    wire = base64.b64decode(data or '', validate=True)
    head, separator, body = wire.partition(b'\r\n\r\n')
    if response and separator and CHUNKED.search(head):
        class BufferedResponse(io.BytesIO):
            def makefile(self, *_args):
                return self

        with http.client.HTTPResponse(BufferedResponse(wire)) as message:
            try:
                message.begin()
                body = message.read()
            except (OSError, ValueError, http.client.HTTPException):
                # A limit-hit reconstruction can retain the original header
                # with dechunked, truncated entity bytes appended after it.
                if not truncated:
                    body = b''
    return head, body if separator else b''


def decoded_json(value):
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def offline_observations(rows, pattern, response_pattern, body_bytes):
    padding = 'x' * body_bytes
    for row in rows:
        truncated = bool(row.get('truncated'))
        head, request = http_message(row.get('request'))
        _, response = http_message(row.get('response'), response=True, truncated=truncated)
        match = pattern.search(head)
        echo = decoded_json(response)
        echoed_body = echo.get('body') if isinstance(echo, dict) else None
        echoed_request = decoded_json(echoed_body)
        response_id = echoed_request.get('marker') if isinstance(echoed_request, dict) else None
        if not match:
            if isinstance(response_id, str) and response_pattern.fullmatch(response_id):
                yield response_id, 'response_only', row.get('backend', 'unknown'), row['id']
            continue
        marker = match[1].decode('ascii')
        # A truncated body can hide the response identity without losing the
        # response half. Report truncation and an absent/mismatched pair separately.
        unpaired = (not row.get('status') or not row.get('response') or
                    (response_id is not None and response_id != marker))
        valid_body = (decoded_json(request) == {'marker': marker, 'message': padding} and
                      isinstance(echoed_body, str) and echoed_body.encode('utf-8') == request)
        mismatch = not (unpaired or truncated) and (row['status'] != 200 or not valid_body)
        yield marker, (unpaired, truncated, bool(row.get('incomplete')), mismatch), row.get('backend', 'unknown'), row['id']


METRICS = {
    'not_dispatched': 'scheduled',
    'business_failed': 'dispatched',
    'raw_observed': 'dispatched',
    'offline_observed': 'dispatched',
    'raw_missing': 'business_success',
    'reconstruction_missing': 'business_success',
    'raw_seen_reconstruction_missing': 'successful_with_raw',
    'raw_duplicate': 'successful_with_raw',
    'offline_duplicate': 'successful_with_offline',
    'unpaired': 'successful_with_offline',
    'body_truncated': 'successful_with_offline',
    'offline_incomplete': 'successful_with_offline',
    'offline_body_or_status_mismatch': 'successful_with_offline',
    'response_without_request_id': 'business_success',
    'offline_without_raw': 'successful_with_offline',
    'complete_pair': 'business_success',
}


def summarize_event(counts, sent, success, raw, offline, unpaired, truncated, incomplete, mismatch, response_only):
    counts['scheduled'] += 1
    counts['dispatched'] += sent
    counts['not_dispatched'] += not sent
    counts['business_failed'] += sent and not success
    counts['raw_observed'] += sent and raw > 0
    counts['offline_observed'] += sent and offline + response_only > 0
    if success:
        counts['business_success'] += 1
        counts['successful_with_raw'] += raw > 0
        counts['successful_with_offline'] += offline > 0
        counts['raw_missing'] += raw == 0
        counts['reconstruction_missing'] += offline == 0
        counts['raw_seen_reconstruction_missing'] += raw > 0 and offline == 0
        counts['raw_duplicate'] += raw > 1
        counts['offline_duplicate'] += offline > 1
        counts['unpaired'] += unpaired > 0
        counts['body_truncated'] += truncated > 0
        counts['offline_incomplete'] += incomplete > 0
        counts['offline_body_or_status_mismatch'] += mismatch > 0
        counts['response_without_request_id'] += response_only > 0
        counts['offline_without_raw'] += offline > 0 and raw == 0
        counts['complete_pair'] += offline == 1 and not (unpaired or truncated or incomplete or mismatch)


def ratio(count, denominator, population):
    return {'count': count, 'denominator': denominator, 'population': population,
            'ratio': count / denominator if denominator else None}


def reconcile(ledger, offset, windows, session, mode, run_id, body_bytes, sidecar, log):
    """Stream the join through a disposable disk-backed database."""
    phase_by_prefix = {f'{run_id}-{phase}': phase for phase in windows}
    marker = '(?:' + '|'.join(re.escape(prefix) for prefix in phase_by_prefix) + r')-[0-9]+'
    marker_pattern = re.compile(marker)
    headers = re.compile(HEADER + b'(' + marker.encode('ascii') +
                         rb')[ \t]*\r?$', re.MULTILINE)
    diagnostics = {'raw_tls_partial_tail': False}
    raw_backends, offline_backends = Counter(), Counter()
    summary = {phase: Counter() for phase in windows}
    with tempfile.TemporaryDirectory(prefix='impact-reconcile-') as folder, \
            closing(sqlite3.connect(Path(folder) / 'join.sqlite')) as db, \
            sidecar.open('x', encoding='utf-8') as output:
        db.execute('''CREATE TABLE evidence(
            id TEXT PRIMARY KEY, phase TEXT, sent INTEGER, success INTEGER,
            raw INTEGER DEFAULT 0, offline INTEGER DEFAULT 0, unpaired INTEGER DEFAULT 0,
            truncated INTEGER DEFAULT 0, incomplete INTEGER DEFAULT 0, mismatch INTEGER DEFAULT 0,
            response_only INTEGER DEFAULT 0)''')
        with ledger.open(encoding='utf-8') as stream:
            stream.seek(offset)
            for line in stream:
                entry = json.loads(line)
                phase = entry['phase']
                if phase not in windows:
                    continue
                validate_ledger_entry(entry, run_id, phase, windows[phase])
                db.execute('INSERT INTO evidence(id, phase, sent, success) VALUES (?, ?, ?, ?)',
                           (entry['id'], phase, entry.get('sent', True), entry['success']))
        if session is not None:
            if mode == 'packets':
                observations = raw_packet_ids(session, headers, Path(folder), log)
            else:
                path = session / 'tls' / 'stream.jsonl'
                observations = raw_tls_ids(path, headers, diagnostics) if path.exists() else ()
            for marker, backend in observations:
                db.execute('INSERT INTO evidence(id,raw) VALUES (?,1) '
                           'ON CONFLICT(id) DO UPDATE SET raw=raw+1', (marker,))
                raw_backends[backend] += 1
            for marker, flags, backend, transaction_id in offline_observations(
                    offline_rows(session), headers, marker_pattern, body_bytes):
                if mode == 'tls' and backend == 'pcap':
                    # Plaintext packet traffic and TLS probe traffic have distinct coverage.
                    offline_backends['excluded:pcap'] += 1
                    continue
                offline_backends[backend] += 1
                output.write(json.dumps({'kind': 'offline_transaction', 'id': marker,
                                         'backend': backend, 'transaction_id': transaction_id,
                                         'response_only': flags == 'response_only'}) + '\n')
                if flags == 'response_only':
                    db.execute('INSERT INTO evidence(id,response_only) VALUES (?,1) '
                               'ON CONFLICT(id) DO UPDATE SET response_only=response_only+1', (marker,))
                else:
                    db.execute('''INSERT INTO evidence(id,offline,unpaired,truncated,incomplete,mismatch)
                        VALUES (?,1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                        offline=offline+1, unpaired=unpaired+excluded.unpaired,
                        truncated=truncated+excluded.truncated, incomplete=incomplete+excluded.incomplete,
                        mismatch=mismatch+excluded.mismatch''', (marker, *flags))
        for marker, phase, sent, success, raw, offline, unpaired, truncated, incomplete, mismatch, response_only in db.execute(
                'SELECT * FROM evidence ORDER BY id'):
            if phase is None:
                phase = phase_by_prefix[marker.rsplit('-', 1)[0]]
            if sent is not None:
                summarize_event(summary[phase], sent, success, raw, offline, unpaired,
                                truncated, incomplete, mismatch, response_only)
            summary[phase]['raw_ids'] += raw > 0
            summary[phase]['offline_evidence_ids'] += offline + response_only > 0
            summary[phase]['unexpected_raw'] += not sent and raw > 0
            summary[phase]['unexpected_offline'] += not sent and offline + response_only > 0
            output.write(json.dumps(dict(kind='request', id=marker, phase=phase,
                                         dispatched=None if sent is None else bool(sent),
                                         business_success=None if success is None else bool(success),
                                         raw_observations=raw, offline_transactions=offline,
                                         unpaired=unpaired, truncated=truncated, incomplete=incomplete,
                                         body_or_status_mismatch=mismatch, response_only=response_only)) + '\n')
    for phase, count in summary.items():
        if count['scheduled'] != windows[phase]:
            raise ValueError(f'{phase}: ledger did not account for all scheduled IDs')
    metrics = dict(METRICS, unexpected_raw='raw_ids', unexpected_offline='offline_evidence_ids')
    return {'windows': {phase: {name: ratio(count[name], count[population], population)
                                for name, population in metrics.items()
                                if session is not None or name in ('not_dispatched', 'business_failed')}
                        for phase, count in summary.items()},
            'raw_observations_by_backend': dict(raw_backends), 'offline_observations_by_backend': dict(offline_backends),
            **diagnostics}


def validate_ledger_entry(entry, run_id, phase, total):
    prefix = f'{run_id}-{phase}-'
    marker = entry.get('id', '')
    index = marker.removeprefix(prefix)
    if (entry.get('phase') != phase or not marker.startswith(prefix) or
            not re.fullmatch(r'0|[1-9][0-9]*', index) or int(index) >= total or
            not isinstance(entry.get('sent', True), bool) or not isinstance(entry.get('success'), bool) or
            (entry.get('sent') is False and entry['success'])):
        raise ValueError('invalid load ledger request')
