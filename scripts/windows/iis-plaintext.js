'use strict';

// HTTP Server API v1 prefixes from the Windows x64 SDK. Buffers are copied only
// after I/O completion. Pre-attach receives are recovered by validating bounded
// pointer references in the completion context, never by reissuing receive I/O.
if (Process.arch !== 'x64') throw new Error('IIS plaintext capture requires x64');
const requestLimit = __REQUEST_LIMIT__;
const responseLimit = __RESPONSE_LIMIT__;
const selectedPorts = new Set(__PORTS__);
const requests = new Map();
const pending = new Map();
const ignored = new Set();
const observedRequests = new Set();
let deferredBytes = 0;
let deferredCount = 0;
const listeners = [];
const originalCode = new Map();
let stopping = false;
const hooked = new Set();
let events = [];
let eventBytes = 0;
let dropped = 0;
let completed = 0;
const captureQueueBytes = 8 * 1024 * 1024;
const maxBodyCopyPerCall = 128 * 1024;
let recoveryBudget = 32;
const diagnostics = {completion_entries: 0, matches: 0,
    recovered_receives: 0, recovery_attempts: 0, recovery_failures: 0,
    receive_matches: 0, body_matches: 0, send_matches: 0, interim_matches: 0,
    unmatched_completions: 0, unmatched_receive: 0, unmatched_body: 0, unmatched_send: 0, unmatched_unknown: 0,
    remove_calls: 0, remove_ex_calls: 0, worker_calls: 0, samples: []};
let unmatchedReported = {receive: 0, body: 0, send: 0, unknown: 0};
const verbs = ['', '', '', 'OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE',
    'TRACE', 'CONNECT', 'TRACK', 'MOVE', 'COPY', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'LOCK', 'UNLOCK', 'SEARCH'];
const commonHeaders = ['Cache-Control', 'Connection', 'Date', 'Keep-Alive', 'Pragma',
    'Trailer', 'Transfer-Encoding', 'Upgrade', 'Via', 'Warning', 'Allow', 'Content-Length',
    'Content-Type', 'Content-Encoding', 'Content-Language', 'Content-Location', 'Content-MD5',
    'Content-Range', 'Expires', 'Last-Modified'];
const requestHeaders = commonHeaders.concat(['Accept', 'Accept-Charset', 'Accept-Encoding',
    'Accept-Language', 'Authorization', 'Cookie', 'Expect', 'From', 'Host', 'If-Match',
    'If-Modified-Since', 'If-None-Match', 'If-Range', 'If-Unmodified-Since', 'Max-Forwards',
    'Proxy-Authorization', 'Referer', 'Range', 'TE', 'Translate', 'User-Agent']);
const responseHeaders = commonHeaders.concat(['Accept-Ranges', 'Age', 'ETag', 'Location',
    'Proxy-Authenticate', 'Retry-After', 'Server', 'Set-Cookie', 'Vary', 'WWW-Authenticate']);

function enqueue(event, data = null) {
    const size = data === null ? 0 : data.byteLength;
    if (events.length >= 512 || eventBytes + size > captureQueueBytes) {
        dropped++;
        return;
    }
    event.time = new Date().toISOString();
    events.push({event, data});
    eventBytes += size;
}

let transportSequence = 0;
function flush() {
    recoveryBudget = 32;
    for (const [id, state] of requests) {
        if (!state.known && Date.now() - state.created > 5000) discard(id);
    }
    const batch = events;
    events = [];
    eventBytes = 0;
    if (dropped > 0) {
        send({type: 'loss', count: dropped, sequence: ++transportSequence});
        dropped = 0;
    }
    for (const item of batch) { item.event.sequence = ++transportSequence; send(item.event, item.data); }
}

function stateFor(id) {
    if (ignored.has(id)) return undefined;
    let state = requests.get(id);
    if (state === undefined && requests.size < 512) {
        state = {request: 0, response: 0, known: false, deferred: [], created: Date.now(), ended: false, lost: false};
        requests.set(id, state);
    }
    return state;
}

function discard(id) {
    const state = requests.get(id);
    if (state === undefined) return;
    for (const item of state.deferred) {
        deferredCount--;
        deferredBytes -= item.data === null ? 0 : item.data.byteLength;
    }
    requests.delete(id);
}

function dispatch(event, data = null) {
    const state = requests.get(event.id);
    if (state === undefined) return;
    if (state.known) { enqueue(event, data); return; }
    const size = data === null ? 0 : data.byteLength;
    if (deferredCount >= 512 || deferredBytes + size > captureQueueBytes) {
        state.lost = true;
        dropped++;
        return;
    }
    state.deferred.push({event, data});
    deferredCount++;
    deferredBytes += size;
}

function gap(id, reason) { dispatch({type: 'gap', id, reason}); }
function key(value) { return '0x' + value.toString(16); }
function text(pointer, length) {
    if (length > 32768) throw new Error('HTTP header exceeds capture limit');
    return length === 0 ? '' : pointer.readUtf8String(length);
}

function headers(base, names) {
    const result = [];
    let bytes = 0;
    function add(name, value) {
        bytes += name.length + value.length;
        if (bytes > 32768) throw new Error('HTTP headers exceed capture limit');
        result.push([name, value]);
    }
    for (let index = 0; index < names.length; index++) {
        const header = base.add(32 + index * 16);
        const length = header.readU16();
        if (length > 0) add(names[index], text(header.add(8).readPointer(), length));
    }
    const count = base.readU16();
    if (count > 256) throw new Error('Too many HTTP headers');
    const unknown = base.add(8).readPointer();
    for (let index = 0; index < count; index++) {
        const header = unknown.add(index * 24);
        add(text(header.add(8).readPointer(), header.readU16()),
            text(header.add(16).readPointer(), header.add(2).readU16()));
    }
    return result;
}

function address(pointer) {
    const family = pointer.readU16();
    const portBytes = new Uint8Array(pointer.add(2).readByteArray(2));
    const port = portBytes[0] * 256 + portBytes[1];
    if (family === 2) {
        const ip = new Uint8Array(pointer.add(4).readByteArray(4));
        return {endpoint: Array.from(ip).join('.') + ':' + port, port};
    }
    if (family === 23) {
        const ip = new Uint8Array(pointer.add(8).readByteArray(16));
        const groups = [];
        for (let index = 0; index < 16; index += 2) groups.push((ip[index] * 256 + ip[index + 1]).toString(16));
        return {endpoint: '[' + groups.join(':') + ']:' + port, port};
    }
    throw new Error('Unsupported socket address family');
}

function body(id, direction, pointer, length, budget = maxBodyCopyPerCall) {
    const state = requests.get(id);
    if (state === undefined || length === 0) return 0;
    const limit = (direction === 'request' ? requestLimit : (state.responseLimit || responseLimit)) || Number.POSITIVE_INFINITY;
    const used = state[direction];
    const clipped = direction + 'Clipped';
    const room = state.known ? captureQueueBytes - eventBytes : captureQueueBytes - deferredBytes;
    const slots = state.known ? 512 - events.length : 512 - deferredCount;
    const count = state[clipped] ? 0 : Math.min(length, Math.max(0, limit - used),
        Math.max(0, room), Math.max(0, slots) * 65536, budget);
    state[direction] += length;
    if (count === 0) dispatch({type: direction + '-body', id, length});
    for (let offset = 0; offset < count; offset += 65536) {
        dispatch({type: direction + '-body', id, length: offset === 0 ? length : 0},
            pointer.add(offset).readByteArray(Math.min(65536, count - offset)));
    }
    if (count < length && !state[clipped]) {
        state[clipped] = true;
        dispatch({type: 'truncated', id});
    }
    return count;
}

const kernel = Process.getModuleByName('kernel32.dll');
const fileSize = new NativeFunction(kernel.getExportByName('GetFileSizeEx'), 'bool', ['pointer', 'pointer']);

function chunks(id, direction, count, pointer) {
    if (!requests.has(id)) return;
    if (count > 256) throw new Error('Too many entity chunks');
    let budget = maxBodyCopyPerCall;
    for (let index = 0; index < count; index++) {
        const chunk = pointer.add(index * 32);
        const type = chunk.readU32();
        if (type === 0) {
            budget -= body(id, direction, chunk.add(8).readPointer(), chunk.add(16).readU32(), budget);
        } else if (type === 1) {
            // Preserve the declared body length without mapping or faulting in
            // file pages on the target's HTTP API callback.
            const rangeOffset = chunk.add(8).readU64();
            const declared = chunk.add(16).readU64();
            let length = declared.toNumber();
            if (declared.toString() === '18446744073709551615') {
                const sizeBuffer = Memory.alloc(8);
                const handle = chunk.add(24).readPointer();
                if (!fileSize(handle, sizeBuffer)) { gap(id, 'Cannot query file chunk size'); continue; }
                length = sizeBuffer.readU64().toNumber() - rangeOffset.toNumber();
            }
            if (!Number.isSafeInteger(length) || length < 0) {
                gap(id, 'Unsupported file chunk range');
                continue;
            }
            if (length > 0) {
                body(id, direction, null, length, 0);
                gap(id, 'File-backed body omitted by live capture');
            }
        } else {
            gap(id, 'Unsupported cached entity chunk type ' + type);
        }
    }
}

function describeRequest(request) {
    // Do not trust a pointer merely because it is readable. These independent
    // public HTTP_REQUEST fields distinguish it from unrelated completed I/O.
    const major = request.add(32).readU16(), minor = request.add(34).readU16();
    if (!((major === 1 && minor <= 1) || (major === 2 && minor === 0))) return null;
    if (request.readU32() > 15 || request.add(8).readU64().compare(0) === 0 || request.add(16).readU64().compare(0) === 0) return null;
    const verb = request.add(36).readU32();
    if (verb > 20) return null;
    const method = verbs[verb] || text(request.add(48).readPointer(), request.add(40).readU16());
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(method)) return null;
    const length = request.add(42).readU16();
    if (length < 1 || length > 32768) return null;
    const url = text(request.add(56).readPointer(), length);
    const authority = method === 'CONNECT' && /^[^\s/]+:\d{1,5}$/.test(url);
    if (!(url.startsWith('/') || url === '*' || /^[a-z]+:\/\//i.test(url) || authority) || /[\r\n\x00]/.test(url)) return null;
    const local = address(request.add(112).readPointer());
    const client = address(request.add(104).readPointer());
    if (!selectedPorts.has(local.port) || client.port < 1 || request.add(840).readPointer().isNull()) return null;
    if (request.add(816).readU16() > 256) return null;
    return {id: key(request.add(16).readU64()), connection: key(request.add(8).readU64()),
        http_version: 'HTTP/' + major + '.' + minor, method, url,
        headers: headers(request.add(120), requestHeaders), client: client.endpoint, local: local.endpoint};
}

function receiveRequest(operation, description = null) {
    const request = operation.buffer;
    const id = key(request.add(16).readU64());
    // A response may be observed by another worker before the receive callback.
    // Hold those events until the request establishes its TLS and port scope.
    const local = address(request.add(112).readPointer());
    if (request.add(840).readPointer().isNull() || !selectedPorts.has(local.port)) {
        discard(id);
        if (ignored.size >= 2048) ignored.clear();
        ignored.add(id);
        return;
    }
    if (observedRequests.has(id)) return;
    const state = stateFor(id);
    if (state === undefined) { dropped++; return; }
    if (state.known) return;
    const details = description || describeRequest(request);
    if (details === null) { gap(id, 'Invalid completed HTTP request'); return; }
    if (observedRequests.size >= 8192) observedRequests.delete(observedRequests.values().next().value);
    observedRequests.add(id);
    state.known = true;
    enqueue(Object.assign({type: 'request'}, details));
    const observed = state.request;
    state.request = 0;
    chunks(id, 'request', request.add(816).readU16(), request.add(824).readPointer());
    state.request += observed;
    if ((request.readU32() & 1) === 0) enqueue({type: 'request-end', id});
    for (const item of state.deferred) {
        deferredCount--;
        deferredBytes -= item.data === null ? 0 : item.data.byteLength;
        enqueue(item.event, item.data);
    }
    state.deferred = [];
    if (state.lost) gap(id, 'Orphan event queue overflow');
    if (state.ended) requests.delete(id);
}

function recoverReceive(overlapped, status, length, expectedId = null) {
    if (status !== 0 || overlapped.isNull()) return false;
    // Most IOCP completions belong to unrelated APIs. Spend a bounded amount
    // of time on speculative recovery and prioritize exact request IDs.
    if (expectedId === null) {
        if (length < 848 || recoveryBudget <= 0) return false;
        recoveryBudget--;
    }
    diagnostics.recovery_attempts++;
    // Bounded read-only discovery, not a process/heap scan or a private layout
    // offset. The callback owns this context until the completion hook returns.
    // Validate every candidate before changing request state or reading bodies.
    for (let offset = 32; offset < 512; offset += Process.pointerSize) {
        let candidate, description;
        try {
            candidate = overlapped.add(offset).readPointer();
            if (candidate.isNull() || !candidate.and(7).isNull()) continue;
            description = describeRequest(candidate);
            if (description === null || (expectedId !== null && description.id !== expectedId)) continue;
        } catch (_) { continue; /* Unrelated/non-readable completion context. */ }
        if (observedRequests.has(description.id)) return true;
        // A zero-byte/non-receive completion may retain a stale request
        // pointer. Require either receive-sized output or an API operation
        // observed in this attach generation for exactly this request ID.
        if (length < 848 && !requests.has(description.id)) continue;
        try {
            receiveRequest({buffer: candidate}, description);
            diagnostics.recovered_receives++;
        } catch (error) {
            diagnostics.recovery_failures++;
            gap(description.id, 'Completed request recovery: ' + String(error));
        }
        return true;
    }
    return false;
}

function complete(operation, status, length) {
    if (operation.done) return;
    operation.done = true;
    try {
        if (operation.kind === 'receive') {
            if (status === 0) receiveRequest(operation);
        } else if (operation.kind === 'body') {
            if (status === 0 || status === 38 || status === 0xc0000011) {
                body(operation.id, 'request', operation.buffer, Math.min(length, operation.capacity));
                if (status !== 0 || length === 0) dispatch({type: 'request-end', id: operation.id});
            } else if (requests.has(operation.id)) gap(operation.id, 'Request body I/O failed: ' + status);
        } else if (operation.kind === 'send') {
            if (status !== 0) gap(operation.id, 'Response I/O failed: ' + status);
            if ((operation.flags & 2) === 0 && requests.has(operation.id)) {
                const state = requests.get(operation.id);
                dispatch({type: 'response-end', id: operation.id});
                state.ended = true;
                if (state.known) requests.delete(operation.id);
                completed++;
            }
        }
    } catch (error) {
        gap(operation.id || '', String(error));
    }
}

function noteUnmatched(kind) {
    diagnostics.unmatched_completions++;
    const key = kind === 'receive' || kind === 'body' || kind === 'send' ? kind : 'unknown';
    diagnostics['unmatched_' + key]++;
    unmatchedReported[key]++;
    // Do not enqueue here. This hook sees every I/O completion in the process.
    // A gap event every few misses would fill the 512-event queue and drop HTTP.
}

function completion(overlapped, status, length) {
    diagnostics.completion_entries++;
    const operation = pending.get(overlapped.toString());
    if (operation === undefined) {
        if (recoverReceive(overlapped, status, length)) return;
        if (diagnostics.samples.length < 8) diagnostics.samples.push({overlapped: overlapped.toString(), pending: Array.from(pending.keys()).slice(0, 8)});
        noteUnmatched('unknown');
        return;
    }
    diagnostics.matches++;
    if (operation.kind === 'receive') diagnostics.receive_matches++;
    else if (operation.kind === 'body') diagnostics.body_matches++;
    else if (operation.kind === 'send') diagnostics.send_matches++;
    else if (operation.kind === 'interim') diagnostics.interim_matches++;
    pending.delete(overlapped.toString());
    complete(operation, status, length);
}

function hook(module, name, callbacks) {
    const location = module.findExportByName(name);
    if (location === null || hooked.has(location.toString())) return;
    hooked.add(location.toString());
    originalCode.set(location.toString(), Array.from(new Uint8Array(location.readByteArray(16))));
    listeners.push(Interceptor.attach(location, callbacks));
}

const ntdll = Process.getModuleByName('ntdll.dll');
function completionReturn(name, first, second, third) {
    return result => {
        if (result.toInt32() !== 0) return;
        try {
            if (first.isNull()) return;
            if (name === 'NtRemoveIoCompletion') {
                if (second.isNull()) return;
                completion(first.readPointer(), second.readU32(), second.add(8).readU64().toNumber());
            } else {
                if (second < 1 || second > 4096 || third.isNull()) return;
                const count = Math.min(third.readU32(), second);
                for (let index = 0; index < count; index++) {
                    const entry = first.add(index * 32);
                    completion(entry.add(8).readPointer(), entry.add(16).readU32(), entry.add(24).readU64().toNumber());
                }
            }
        } catch (_) { noteUnmatched('unknown'); }
    };
}

hook(ntdll, 'NtRemoveIoCompletion', {
    onEnter(args) {
        if (stopping) return;
        diagnostics.remove_calls++;
        this.complete = completionReturn('NtRemoveIoCompletion', args[2], args[3]);
    },
    onLeave(result) {
        if (!stopping && this.complete !== undefined) this.complete(result);
    }
});
for (const name of ['NtRemoveIoCompletionEx', 'NtWaitForWorkViaWorkerFactory']) {
    hook(ntdll, name, {
        onEnter(args) {
            if (stopping) return;
            if (name === 'NtRemoveIoCompletionEx') diagnostics.remove_ex_calls++;
            else diagnostics.worker_calls++;
            const entries = args[1];
            const capacity = args[2].toUInt32();
            const countPointer = args[3];
            this.complete = completionReturn(name, entries, capacity, countPointer);
        },
        onLeave(result) {
            if (!stopping && this.complete !== undefined) this.complete(result);
        }
    });
}

const httpapi = Process.getModuleByName('httpapi.dll');
for (const name of ['HttpReceiveHttpRequest', 'HttpReceiveRequestEntityBody', 'HttpSendHttpResponse', 'HttpSendResponseEntityBody']) {
    hook(httpapi, name, {
        onEnter(args) {
            if (stopping) return;
            const receiving = name === 'HttpReceiveHttpRequest';
            const bodyRead = name === 'HttpReceiveRequestEntityBody';
            const operation = {kind: receiving ? 'receive' : bodyRead ? 'body' : 'send',
                id: args[1].toString(), buffer: args[3], capacity: args[4].toUInt32(),
                bytes: args[5], flags: args[2].toUInt32(), done: false};
            const overlap = args[receiving || bodyRead ? 6 : 8];
            operation.overlap = overlap.toString();
            this.operation = operation;
            if (!overlap.isNull()) {
                if (!pending.has(operation.overlap) && pending.size >= 4096) {
                    pending.delete(pending.keys().next().value);
                    dropped++;
                }
                pending.set(operation.overlap, operation);
            }
            if (!receiving && stateFor(operation.id) !== undefined) {
                // The response/body API still owns the request context, even
                // when its original receive or dequeue began before attach.
                // Match the exact API request ID before recovering that buffer.
                recoverReceive(overlap, 0, 0, operation.id);
            }
            if (!receiving && stateFor(operation.id) !== undefined && !bodyRead) {
                try {
                    if (name === 'HttpSendHttpResponse') {
                        const response = args[3];
                        const status = response.add(8).readU16();
                        if (status < 200) { operation.kind = 'interim'; return; }
                        const fields = headers(response.add(24), responseHeaders);
                        if (fields.some(field => field[0].toLowerCase() === 'transfer-encoding' && field[1].toLowerCase().includes('chunked'))) {
                            requests.get(operation.id).responseLimit = responseLimit ? responseLimit * 8 + 32768 : 0;
                        }
                        dispatch({type: 'response', id: operation.id, status, headers: fields});
                        chunks(operation.id, 'response', response.add(536).readU16(), response.add(544).readPointer());
                    } else {
                        chunks(operation.id, 'response', args[3].toUInt32(), args[4]);
                    }
                } catch (error) { gap(operation.id, String(error)); }
            }
        },
        onLeave(result) {
            const operation = this.operation;
            if (stopping || operation === undefined) return;
            const status = result.toUInt32();
            if (status === 997) return;
            if (pending.get(operation.overlap) === operation) pending.delete(operation.overlap);
            const length = operation.bytes.isNull() ? 0 : operation.bytes.readU32();
            complete(operation, status, length);
        }
    });
}
const timer = setInterval(flush, 50);
enqueue({type: 'ready', protocol: 'traffic-iis-v1', pid: Process.id,
    startup_receive_recovery: 'validated-completion-context', startup_receive_gap_possible: true});
rpc.exports = {
    finish() {
        stopping = true;
        for (const listener of listeners) listener.detach();
        Interceptor.flush();
        let restored = true;
        for (const [address, original] of originalCode) {
            const actual = new Uint8Array(ptr(address).readByteArray(16));
            if (original.some((value, index) => value !== actual[index])) restored = false;
        }
        clearInterval(timer);
        for (const [id, state] of requests) {
            if (state.known) gap(id, 'Capture stopped before response completed');
        }
        // One record at stop. The completion has no operation kind, so the
        // reason stays unmatched_completion. The collector decides the attach
        // window from receive_matches versus send_matches.
        // Drain queued sequence numbers before emitting the final direct record.
        flush();
        if (unmatchedReported.unknown > 0) {
            send({type: 'probe-gap', reason: 'unmatched_completion', kind: 'unknown', count: unmatchedReported.unknown, time: new Date().toISOString(), sequence: ++transportSequence, final: true});
        }
        const plaintextObserved = observedRequests.size > 0;
        return {type: 'summary', last_sequence: transportSequence, completed, pending: pending.size, diagnostics,
            plaintext_observed: plaintextObserved,
            attach_window_suspect: !plaintextObserved && diagnostics.unmatched_completions > 0 && diagnostics.send_matches > 0,
            hooks_removed: restored, restored_sites: originalCode.size, plaintext_verified: false};
    }
};
