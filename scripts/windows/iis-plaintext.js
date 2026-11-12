'use strict';

// HTTP Server API v1 prefixes from the Windows x64 SDK. No private IIS object
// layouts are read. Buffers are copied only after receive I/O has completed.
if (Process.arch !== 'x64') throw new Error('IIS plaintext capture requires x64');
const requestLimit = __REQUEST_LIMIT__;
const responseLimit = __RESPONSE_LIMIT__;
const selectedPorts = new Set(__PORTS__);
const requests = new Map();
const pending = new Map();
const ignored = new Set();
let deferredBytes = 0;
let deferredCount = 0;
const listeners = [];
const originalCode = new Map();
const returnFrames = new Map();
const returnLocations = new Set();
let stopping = false;
const hooked = new Set();
let events = [];
let eventBytes = 0;
let dropped = 0;
let completed = 0;
const diagnostics = {completion_entries: 0, matches: 0, remove_calls: 0, remove_ex_calls: 0, worker_calls: 0, samples: []};
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
    if (events.length >= 512 || eventBytes + size > 8 * 1024 * 1024) {
        dropped++;
        return;
    }
    event.time = new Date().toISOString();
    events.push({event, data});
    eventBytes += size;
}

function flush() {
    for (const [id, state] of requests) {
        if (!state.known && Date.now() - state.created > 5000) discard(id);
    }
    const batch = events;
    events = [];
    eventBytes = 0;
    if (dropped > 0) {
        send({type: 'loss', count: dropped});
        dropped = 0;
    }
    for (const item of batch) send(item.event, item.data);
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
    if (deferredCount >= 512 || deferredBytes + size > 8 * 1024 * 1024) {
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

const kernel = Process.getModuleByName('kernel32.dll');
const createMapping = new NativeFunction(kernel.getExportByName('CreateFileMappingW'), 'pointer',
    ['pointer', 'pointer', 'uint', 'uint', 'uint', 'pointer']);
const mapView = new NativeFunction(kernel.getExportByName('MapViewOfFile'), 'pointer',
    ['pointer', 'uint', 'uint', 'uint', 'ulong']);
const unmapView = new NativeFunction(kernel.getExportByName('UnmapViewOfFile'), 'bool', ['pointer']);
const closeHandle = new NativeFunction(kernel.getExportByName('CloseHandle'), 'bool', ['pointer']);
const fileSize = new NativeFunction(kernel.getExportByName('GetFileSizeEx'), 'bool', ['pointer', 'pointer']);

function body(id, direction, pointer, length) {
    const state = requests.get(id);
    if (state === undefined || length === 0) return;
    const limit = direction === 'request' ? requestLimit : (state.responseLimit || responseLimit);
    const used = state[direction];
    const count = Math.min(length, Math.max(0, limit - used));
    state[direction] += length;
    if (count === 0) dispatch({type: direction + '-body', id, length});
    for (let offset = 0; offset < count; offset += 65536) {
        dispatch({type: direction + '-body', id, length: offset === 0 ? length : 0},
            pointer.add(offset).readByteArray(Math.min(65536, count - offset)));
    }
    if (used <= limit && used + length > limit) dispatch({type: 'truncated', id});
}

function chunks(id, direction, count, pointer) {
    if (!requests.has(id)) return;
    if (count > 256) throw new Error('Too many entity chunks');
    for (let index = 0; index < count; index++) {
        const chunk = pointer.add(index * 32);
        const type = chunk.readU32();
        if (type === 0) {
            body(id, direction, chunk.add(8).readPointer(), chunk.add(16).readU32());
        } else if (type === 1) {
            const handle = chunk.add(24).readPointer();
            const sizeBuffer = Memory.alloc(8);
            if (!fileSize(handle, sizeBuffer)) { gap(id, 'Cannot query file chunk size'); continue; }
            const offset = chunk.add(8).readU64().toNumber();
            const declared = chunk.add(16).readU64();
            const size = sizeBuffer.readU64().toNumber();
            const length = declared.toString() === '18446744073709551615' ? size - offset : declared.toNumber();
            if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || length < 0) {
                gap(id, 'Unsupported file chunk range');
                continue;
            }
            const state = requests.get(id);
            const limit = direction === 'request' ? requestLimit : (state.responseLimit || responseLimit);
            const wanted = Math.min(length, Math.max(0, limit - state[direction]));
            if (wanted === 0) {
                state[direction] += length;
                if (length > 0) {
                    dispatch({type: direction + '-body', id, length});
                    dispatch({type: 'truncated', id});
                }
                continue;
            }
            // A read-only view preserves the server's file position and handle.
            const mapping = createMapping(handle, ptr(0), 2, 0, 0, ptr(0));
            if (mapping.isNull()) { gap(id, 'Cannot map file chunk'); continue; }
            const aligned = Math.floor(offset / 65536) * 65536;
            const delta = offset - aligned;
            const view = mapView(mapping, 4, Math.floor(aligned / 4294967296), aligned % 4294967296, wanted + delta);
            try {
                if (view.isNull()) gap(id, 'Cannot read file chunk');
                else body(id, direction, view.add(delta), length);
            } finally {
                if (!view.isNull()) unmapView(view);
                closeHandle(mapping);
            }
        } else {
            gap(id, 'Unsupported cached entity chunk type ' + type);
        }
    }
}

function receiveRequest(operation) {
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
    const state = stateFor(id);
    if (state === undefined) { dropped++; return; }
    state.known = true;
    const verb = request.add(36).readU32();
    const method = verbs[verb] || text(request.add(48).readPointer(), request.add(40).readU16());
    enqueue({type: 'request', id, connection: key(request.add(8).readU64()), method,
        url: text(request.add(56).readPointer(), request.add(42).readU16()),
        headers: headers(request.add(120), requestHeaders),
        client: address(request.add(104).readPointer()).endpoint, local: local.endpoint});
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

function completion(overlapped, status, length) {
    diagnostics.completion_entries++;
    const operation = pending.get(overlapped.toString());
    if (operation === undefined) {
        if (diagnostics.samples.length < 8) diagnostics.samples.push({overlapped: overlapped.toString(), pending: Array.from(pending.keys()).slice(0, 8)});
        return;
    }
    diagnostics.matches++;
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

// Entry-only hooks leave no JavaScript onLeave invocation parked inside an
// indefinitely blocked receive/dequeue call. Read the result at its caller's
// return site, and remove both entry and return-site patches when stopping.
function atReturn(threadId, location, callback) {
    if (stopping) return;
    const address = location.toString();
    if (!returnLocations.has(address)) {
        returnLocations.add(address);
        originalCode.set(address, Array.from(new Uint8Array(location.readByteArray(16))));
        listeners.push(Interceptor.attach(location, {
            onEnter() {
                if (stopping) return;
                const stack = returnFrames.get(this.threadId);
                if (stack === undefined || stack.length === 0) return;
                const frame = stack[stack.length - 1];
                if (frame.address !== address) return;
                stack.pop();
                if (stack.length === 0) returnFrames.delete(this.threadId);
                frame.callback(this.context.rax);
            }
        }));
    }
    let stack = returnFrames.get(threadId);
    if (stack === undefined) {
        stack = [];
        returnFrames.set(threadId, stack);
    }
    if (stack.length >= 32) { dropped++; return; }
    stack.push({address, callback});
}

const ntdll = Process.getModuleByName('ntdll.dll');
hook(ntdll, 'NtRemoveIoCompletion', {
    onEnter(args) {
        if (stopping) return;
        diagnostics.remove_calls++;
        const apc = args[2];
        const io = args[3];
        atReturn(this.threadId, this.returnAddress, result => {
            if (result.toInt32() === 0) completion(apc.readPointer(), io.readU32(), io.add(8).readU64().toNumber());
        });
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
            atReturn(this.threadId, this.returnAddress, result => {
                if (result.toInt32() !== 0 || capacity < 1 || capacity > 4096 || countPointer.isNull()) return;
                const count = Math.min(countPointer.readU32(), capacity);
                for (let index = 0; index < count; index++) {
                    const entry = entries.add(index * 32);
                    completion(entry.add(8).readPointer(), entry.add(16).readU32(), entry.add(24).readU64().toNumber());
                }
            });
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
            atReturn(this.threadId, this.returnAddress, result => {
                const status = result.toUInt32();
                if (status === 997) return;
                if (pending.get(operation.overlap) === operation) pending.delete(operation.overlap);
                const length = operation.bytes.isNull() ? 0 : operation.bytes.readU32();
                complete(operation, status, length);
            });
            if (!overlap.isNull()) {
                if (pending.size >= 4096) { pending.clear(); dropped++; }
                pending.set(operation.overlap, operation);
            }
            if (!receiving && stateFor(operation.id) !== undefined && !bodyRead) {
                try {
                    if (name === 'HttpSendHttpResponse') {
                        const response = args[3];
                        const status = response.add(8).readU16();
                        if (status < 200) { operation.kind = 'interim'; return; }
                        const fields = headers(response.add(24), responseHeaders);
                        if (fields.some(field => field[0].toLowerCase() === 'transfer-encoding' && field[1].toLowerCase().includes('chunked'))) {
                            requests.get(operation.id).responseLimit = responseLimit * 8 + 32768;
                        }
                        dispatch({type: 'response', id: operation.id, status, headers: fields});
                        chunks(operation.id, 'response', response.add(536).readU16(), response.add(544).readPointer());
                    } else {
                        chunks(operation.id, 'response', args[3].toUInt32(), args[4]);
                    }
                } catch (error) { gap(operation.id, String(error)); }
            }
        }
    });
}
const timer = setInterval(flush, 50);
enqueue({type: 'ready', protocol: 'traffic-iis-v1', pid: Process.id, startup_receive_gap_possible: true});
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
        returnFrames.clear();
        for (const [id, state] of requests) {
            if (state.known) gap(id, 'Capture stopped before response completed');
        }
        flush();
        return {type: 'summary', completed, pending: pending.size, diagnostics, hooks_removed: restored, restored_sites: originalCode.size, plaintext_verified: false};
    }
};
