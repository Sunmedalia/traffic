'use strict';
// Exercise the actual probe with an in-memory public HTTP_REQUEST/OVERLAPPED
// fixture. No IIS private offsets, native calls, or synthetic network service.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, 'iis-plaintext.js'), 'utf8')
    .replace('__REQUEST_LIMIT__', '0').replace('__RESPONSE_LIMIT__', '0').replace('__PORTS__', '[8443]');

function fixture(options = {}) {
    const memory = Buffer.alloc(options.memoryBytes || (1 << 20));
    let allocated = 0x10000, exported = 0x1000;
    const exports = new Map();
    const callbacks = new Map();
    function exportedPointer(name) { if (!exports.has(name)) exports.set(name, new Pointer(exported += 64)); return exports.get(name); }
    class U64 {
        constructor(value) { this.value = BigInt(value); }
        compare(value) { const other = value instanceof U64 ? value.value : BigInt(value); return this.value < other ? -1 : this.value > other ? 1 : 0; }
        toString(radix = 10) { return this.value.toString(radix); }
        toNumber() { return Number(this.value); }
    }
    class Pointer {
        constructor(value) { this.value = Number(value instanceof Pointer ? value.value : value); }
        add(n) { return new Pointer(this.value + n); }
        and(n) { return new Pointer(BigInt(this.value) & BigInt(n)); }
        isNull() { return this.value === 0; }
        compare(other) { return this.value - other.value; }
        toUInt32() { return this.value >>> 0; }
        toInt32() { return this.value | 0; }
        toString() { return '0x' + this.value.toString(16); }
        readU16() { return memory.readUInt16LE(this.value); }
        readU32() { return memory.readUInt32LE(this.value); }
        readU64() { return new U64(memory.readBigUInt64LE(this.value)); }
        readPointer() { return new Pointer(memory.readBigUInt64LE(this.value)); }
        readUtf8String(n) { if (this.value + n > memory.length) throw Error('unreadable'); return memory.toString('utf8', this.value, this.value + n); }
        readByteArray(n) { if (this.value + n > memory.length) throw Error('unreadable'); return Uint8Array.from(memory.subarray(this.value, this.value + n)).buffer; }
    }
    function allocate(size) { const p = new Pointer(allocated); allocated += (size + 7) & ~7; return p; }
    function u16(p, n, value) { memory.writeUInt16LE(value, p.value + n); }
    function u32(p, n, value) { memory.writeUInt32LE(value, p.value + n); }
    function u64(p, n, value) { memory.writeBigUInt64LE(BigInt(value instanceof Pointer ? value.value : value), p.value + n); }
    function string(value) { const bytes = Buffer.from(value); const p = allocate(bytes.length); bytes.copy(memory, p.value); return p; }
    function sockaddr(port) { const p = allocate(32); u16(p, 0, 2); memory.writeUInt16BE(port, p.value + 2); memory.set([127, 0, 0, 1], p.value + 4); return p; }
    const sentMessages = [];
    const nativeImpls = options.nativeImpls || {};
    let currentExport = '';
    const context = vm.createContext({
        Process: {id: 4242, arch: 'x64', pointerSize: 8, findRangeByAddress: () => ({protection: 'r-x'}), enumerateThreads: () => [], getModuleByName: () => ({
            getExportByName: name => { currentExport = name; return exportedPointer(name); },
            findExportByName: name => { currentExport = name; return exportedPointer(name); }
        })},
        Memory: {alloc: allocate},
        NativeFunction: function () {
            const name = currentExport;
            if (nativeImpls[name]) return nativeImpls[name]({Pointer, allocate, u64, memory});
            return () => new Pointer(0);
        },
        Interceptor: {attach: (pointer, handler) => { callbacks.set(pointer.toString(), handler); return {detach() {}}; }, flush() {}},
        ptr: value => new Pointer(value),
        send(event, data = null) { sentMessages.push({event, data}); },
        rpc: {}, setInterval() {}, clearInterval() {}
    });
    vm.runInContext(source, context);
    const request = allocate(864), overlap = allocate(1024), data = string('hello');
    u64(request, 8, 0xff00112233445566n); u64(request, 16, 0xfe00112233445577n);
    u16(request, 32, 1); u16(request, 34, 1); u32(request, 36, 6);
    const url = options.url || '/startup?index=1'; u16(request, 42, Buffer.byteLength(url)); u64(request, 56, string(url));
    u64(request, 104, sockaddr(12345)); u64(request, 112, sockaddr(options.port || 8443));
    u64(request, 840, options.plaintext ? 0 : allocate(16));
    const chunks = allocate(32); u32(chunks, 0, 0); u32(chunks, 16, 5); u64(chunks, 8, data);
    u16(request, 816, 1); u64(request, 824, chunks);
    // Deliberately vary this location; the probe must discover, not hard-code it.
    u64(overlap, options.offset || 184, request);
    context.request = request; context.overlap = overlap;
    function evaluate(code) { return vm.runInContext(code, context); }
    function value(code) { return JSON.parse(evaluate('JSON.stringify(' + code + ')')); }
    return {evaluate, value, memory, u16, u32, u64, string, sockaddr, request, overlap, data, allocate, exportedPointer, context, callbacks, sentMessages, Pointer};
}

for (const offset of [32, 184, 504]) {
    const f = fixture({offset});
    f.evaluate('completion(overlap, 0, 900)');
    const events = f.value('events.map(x => x.event)');
    assert.equal(events.filter(x => x.type === 'request').length, 1);
    assert.equal(events.find(x => x.type === 'request').url, '/startup?index=1');
    assert.equal(events.find(x => x.type === 'request').method, 'POST');
    assert.equal(f.value('diagnostics.recovered_receives'), 1);
    assert.equal(f.value('diagnostics.unmatched_completions'), 0);
    assert.deepEqual(f.value("Array.from(new Uint8Array(events.find(x => x.event.type === 'request-body').data))"), [...Buffer.from('hello')]);
    // The registered completion may arrive after the recovery. Never duplicate
    // the request, its body, or a late completion after the response has ended.
    f.evaluate("requests.delete(key(request.add(16).readU64())); receiveRequest({buffer: request}); completion(overlap, 0, 900)");
    assert.equal(f.value("events.filter(x => x.event.type === 'request').length"), 1);
    assert.equal(f.value('requests.size'), 0);
}

{
    const f = fixture();
    f.evaluate("const id = key(request.add(16).readU64()); stateFor(id); dispatch({type:'response',id,status:200}); dispatch({type:'response-end',id}); requests.get(id).ended=true; completion(overlap,0,0)");
    assert.deepEqual(f.value("events.map(x => x.event.type).filter(x => x !== 'ready')"), ['request', 'request-body', 'request-end', 'response', 'response-end']);
    assert.equal(f.value('deferredBytes'), 0); assert.equal(f.value('deferredCount'), 0); assert.equal(f.value('requests.size'), 0);
}

for (const options of [{plaintext: true}, {port: 443}, {url: '/bad\r\nurl'}]) {
    const f = fixture(options); f.evaluate('completion(overlap,0,900)');
    assert.equal(f.value("events.filter(x => x.event.type === 'request').length"), 0);
    assert.equal(f.value('requests.size'), 0);
    assert.equal(f.value('diagnostics.unmatched_completions'), 1);
}

{
    const f = fixture(); f.evaluate('completion(overlap,0xc0000120,0)');
    assert.equal(f.value("events.filter(x => x.event.type === 'request').length"), 0);
    assert.equal(f.value('diagnostics.recovery_attempts'), 0);
}
{
    const f = fixture(); f.u64(f.overlap, 184, 0x7fffffff);
    f.evaluate('completion(overlap,0,900)');
    assert.equal(f.value('requests.size'), 0);
}
{
    const f = fixture();
    const chunkAddress = Number(f.memory.readBigUInt64LE(f.request.value + 824));
    f.memory.writeBigUInt64LE(0x7fffffff0n, chunkAddress + 8);
    f.evaluate('completion(overlap,0,900)');
    assert.equal(f.value('diagnostics.recovery_failures'), 1);
    assert.equal(f.value("events.filter(x => x.event.type === 'gap').length"), 1);
}
{
    const f = fixture(); f.evaluate('completion(overlap,0,0)');
    assert.equal(f.value('requests.size'), 0);
    assert.equal(f.value("events.filter(x => x.event.type === 'request').length"), 0);
}
{
    const f = fixture();
    // Thread contexts may expose clobbered output registers at attachment.
    // They must not abort the helper or turn unrelated completions into HTTP.
    f.evaluate("completionReturn('NtRemoveIoCompletion', ptr(0), ptr(0))(ptr(0))");
    f.evaluate("completionReturn('NtRemoveIoCompletionEx', ptr(0), 1, ptr(0))(ptr(0))");
    f.evaluate("completionReturn('NtRemoveIoCompletion', ptr(0x7fffffff), ptr(0x7fffffff))(ptr(0))");
    assert.equal(f.value("events.filter(x => x.event.type === 'request').length"),0);
    assert.equal(f.value('diagnostics.unmatched_completions'),1);
}
{
    const f = fixture();
    f.evaluate("stateFor(key(request.add(16).readU64())); recoverReceive(overlap,0,0,'0x123')");
    assert.equal(f.value("events.filter(x=>x.event.type==='request').length"),0);
    f.evaluate("recoverReceive(overlap,0,0,key(request.add(16).readU64()))");
    assert.equal(f.value("events.filter(x=>x.event.type==='request').length"),1);
}
{
    const f = fixture(); const bytes=f.allocate(4),out=f.allocate(16);
    f.u32(bytes,0,5);f.memory.set(Buffer.from('world'),out.value);
    const id=0xfe00112233445577n;
    const h=f.callbacks.get(f.exportedPointer('HttpReceiveRequestEntityBody').toString());
    const call={};const args=[f.allocate(8),{toString:()=> '0x'+id.toString(16)}, {toUInt32:()=>0},out,{toUInt32:()=>16},bytes,f.overlap];
    h.onEnter.call(call,args);h.onLeave.call(call,{toUInt32:()=>0});
    assert.equal(f.value("events.filter(x=>x.event.type==='request').length"),1);
    assert.equal(f.value("events.filter(x=>x.event.type==='request-body').length"),2);
    h.onLeave.call(call,{toUInt32:()=>0});
    assert.equal(f.value("events.filter(x=>x.event.type==='request-body').length"),2);
}
{
    const f=fixture();const response=f.allocate(552),payload=f.allocate(32),body=f.allocate(5),sent=f.allocate(4);
    f.memory.set(Buffer.from('reply'),body.value);f.u16(response,8,200);f.u16(response,536,1);f.u64(response,544,payload);f.u64(payload,8,body);f.u32(payload,16,5);f.u32(sent,0,5);
    const h=f.callbacks.get(f.exportedPointer('HttpSendHttpResponse').toString());
    const zero=f.allocate(0);zero.value=0;
    const args=[zero,{toString:()=> '0xfe00112233445577'},zero,response,zero,sent,zero,zero,f.overlap];
    const call={};h.onEnter.call(call,args);h.onLeave.call(call,{toUInt32:()=>0});
    assert.equal(f.value("events.filter(x=>x.event.type==='request').length"),1);
    assert.equal(f.value("events.filter(x=>x.event.type==='response-end').length"),1);
    assert.equal(f.value('requests.size'),0);
}

// Regression (P2): Out-of-LIFO concurrent IOCP completions across interleaved invocations
// must both succeed without wedging per-thread return stacks, including offsets > 512.
{
    const f = fixture({offset: 896});
    const req2 = f.allocate(864), ov2 = f.allocate(1024);
    f.u64(req2, 8, 0xff00112233445588n); f.u64(req2, 16, 0xfe00112233445599n);
    f.u16(req2, 32, 1); f.u16(req2, 34, 1); f.u32(req2, 36, 4); // GET
    const u2 = '/concurrent?n=2'; f.u16(req2, 42, Buffer.byteLength(u2)); f.u64(req2, 56, f.string(u2));
    f.u64(req2, 104, f.sockaddr(23456)); f.u64(req2, 112, f.sockaddr(8443));
    f.u64(req2, 840, f.allocate(16)); f.u16(req2, 816, 0);
    // Sprinkle non-canonical / low integer values before the real pointer at offset 960.
    f.u64(ov2, 64, 0x1000n);
    f.u64(ov2, 72, 0xffff800000000000n);
    f.u64(ov2, 960, req2);

    const entries1 = f.allocate(32), count1 = f.allocate(4);
    f.u64(entries1, 8, f.overlap); f.u32(entries1, 16, 0); f.u64(entries1, 24, 900n); f.u32(count1, 0, 1);
    const entries2 = f.allocate(32), count2 = f.allocate(4);
    f.u64(entries2, 8, ov2); f.u32(entries2, 16, 0); f.u64(entries2, 24, 900n); f.u32(count2, 0, 1);

    const iocpHook = f.callbacks.get(f.exportedPointer('NtRemoveIoCompletionEx').toString());
    const callA = {}, callB = {};
    const zero = new f.Pointer(0);
    iocpHook.onEnter.call(callA, [zero, entries1, {toUInt32: () => 4}, count1]);
    iocpHook.onEnter.call(callB, [zero, entries2, {toUInt32: () => 4}, count2]);
    // Leave out of LIFO order: callA finishes before callB!
    iocpHook.onLeave.call(callA, {toInt32: () => 0});
    iocpHook.onLeave.call(callB, {toInt32: () => 0});
    assert.equal(f.value("events.filter(x => x.event.type === 'request').length"), 2);
    assert.equal(f.value('diagnostics.recovered_receives'), 2);
}

// Reused completion contexts can retain an earlier, already captured request
// before the new buffer. Cover 100 sequential requests and batches of five.
for (const concurrent of [1, 5]) {
    const f = fixture({offset: 32});
    f.evaluate('completion(overlap, 0, 900); flush()');
    const lanes = Array.from({length: concurrent}, () => {
        const current = f.allocate(864), overlap = f.allocate(1024);
        f.memory.copy(f.memory, current.value, f.request.value, f.request.value + 864);
        f.u64(overlap, 32, f.request);
        f.u64(overlap, 184, current);
        return {current, overlap};
    });
    const entries = f.allocate(concurrent * 32), count = f.allocate(4);
    f.u32(count, 0, concurrent);
    for (let base = 1; base <= 100; base += concurrent) {
        for (const [offset, {current, overlap}] of lanes.entries()) {
            const index = base + offset;
            f.u64(current, 16, 0xfe00000000000000n + BigInt(index));
            const url = '/traffic-test/?n=' + index;
            f.u16(current, 42, Buffer.byteLength(url));
            f.u64(current, 56, f.string(url));
            f.u64(entries, offset * 32 + 8, overlap);
            f.u64(entries, offset * 32 + 24, 900n);
        }
        f.evaluate(`completionReturn('NtRemoveIoCompletionEx', ptr(${entries.value}), ${concurrent}, ptr(${count.value}))(ptr(0)); flush()`);
    }
    const urls = f.sentMessages.filter(item => item.event.type === 'request').map(item => item.event.url);
    assert.equal(urls.length, 101);
    assert.equal(new Set(urls).size, 101);
    assert.equal(urls.at(-1), '/traffic-test/?n=100');
}

// Regression (P3): Plain HTTP request (pSslInfo == NULL) marked ignored must not inflate
// send_matches or trigger false attach_window_suspect when HttpSendHttpResponse runs.
{
    const f = fixture({plaintext: true});
    const recvHook = f.callbacks.get(f.exportedPointer('HttpReceiveHttpRequest').toString());
    const sendHook = f.callbacks.get(f.exportedPointer('HttpSendHttpResponse').toString());
    const zero = new f.Pointer(0), bytes = f.allocate(4); f.u32(bytes, 0, 900);
    const recvCall = {};
    recvHook.onEnter.call(recvCall, [zero, {toString: () => '0x0'}, {toUInt32: () => 0}, f.request, {toUInt32: () => 900}, bytes, f.overlap]);
    recvHook.onLeave.call(recvCall, {toUInt32: () => 0});

    const response = f.allocate(552), sent = f.allocate(4), sendOv = f.allocate(64);
    f.u16(response, 8, 200); f.u32(sent, 0, 0);
    const sendCall = {};
    sendHook.onEnter.call(sendCall, [zero, {toString: () => '0xfe00112233445577'}, {toUInt32: () => 0}, response, {toUInt32: () => 0}, sent, zero, zero, sendOv]);
    f.evaluate(`completion(ptr(${sendOv.value}), 0, 0)`);
    const summary = f.evaluate('rpc.exports.finish()');
    assert.equal(summary.diagnostics.send_matches, 0);
    assert.equal(summary.attach_window_suspect, false);
}

// Regression (P6): Deferred response whose request was never matched/recovered must emit
// explicit loss and unrecovered_receive probe-gap at finish(), never silently vanish.
{
    const f = fixture();
    f.evaluate("stateFor('0xdeadbeef'); dispatch({type: 'response', id: '0xdeadbeef', status: 200});");
    const summary = f.evaluate('rpc.exports.finish()');
    assert.equal(summary.diagnostics.unmatched_receive, 1);
    assert.equal(f.sentMessages.some(m => m.event.type === 'loss' && m.event.count >= 1), true);
    assert.equal(f.sentMessages.some(m => m.event.type === 'probe-gap' && m.event.reason === 'unrecovered_receive' && m.event.count === 1), true);
}

// Regression: File-backed bodies retain their declared length and report omissions,
// and pending map evicts single oldest entry instead of clearing all 4096 entries.
{
    let mapped = false;
    const f = fixture({
        nativeImpls: {
            GetFileSizeEx: ({u64}) => (_handle, sizeBuf) => { u64(sizeBuf, 0, 100n * 1024n * 1024n); return 1; },
            CreateFileMappingW: ({Pointer}) => () => new Pointer(0x50000),
            MapViewOfFile: () => () => { mapped = true; throw new Error("unexpected file mapping"); },
            UnmapViewOfFile: () => () => 1,
            CloseHandle: () => () => 1
        }
    });
    f.evaluate('receiveRequest({buffer: request})');
    f.evaluate("requests.set('0xfe00112233445577', {request: 0, response: 0, known: true, deferred: [], created: Date.now(), ended: false, lost: false})");
    const fileChunk = f.allocate(32);
    f.u32(fileChunk, 0, 1); // HttpDataChunkFromFileHandle
    f.u64(fileChunk, 8, 0n);
    f.u64(fileChunk, 16, 0xffffffffffffffffn);
    f.u64(fileChunk, 24, 0x1234n);
    f.evaluate(`chunks('0xfe00112233445577', 'response', 1, ptr(${fileChunk.value}))`);
    assert.equal(mapped, false);
    assert.equal(f.value("events.find(x => x.event.type === 'response-body').event.length"), 100 * 1024 * 1024);
    assert.equal(f.value("events.some(x => x.event.type === 'gap' && x.event.reason.includes('File-backed body'))"), true);
    assert.equal(f.value("events.some(x => x.event.type === 'truncated')"), true);

    f.evaluate('for (let i = 0; i < 4096; i++) pending.set("ov-" + i, {id: "0x1", kind: "send"});');
    const recvHook = f.callbacks.get(f.exportedPointer('HttpReceiveHttpRequest').toString());
    const zero = new f.Pointer(0);
    recvHook.onEnter.call({}, [zero, {toString: () => '0x0'}, {toUInt32: () => 0}, f.request, {toUInt32: () => 900}, zero, f.overlap]);
    assert.equal(f.value('pending.size'), 4096);
    assert.equal(f.value('pending.has("ov-0")'), false);
    assert.equal(f.value('pending.has("ov-1")'), true);
}

// Regression: openssl-plaintext.js preserves payloads > 64 KiB when limits are 0,
// caches (ssl, fd) endpoints across reads/writes, and copies SSL_write only on success.
{
    const opensslSource = fs.readFileSync(require('node:path').join(__dirname, 'openssl-plaintext.js'), 'utf8')
        .replace('__PORTS__', '[443]').replace('__PROFILES__', '[]').replace('__LIBRARY__', '""')
        .replace('__REQUEST_LIMIT__', '0').replace('__RESPONSE_LIMIT__', '0');
    const sslHooks = new Map();
    const sslMem = Buffer.alloc(256 * 1024, 0x41);
    let localAddrCalls = 0, readByteCalls = 0;
    class SSLPtr {
        constructor(v) { this.v = v; }
        toString() { return '0x' + this.v.toString(16); }
        toUInt32() { return this.v >>> 0; }
        toInt32() { return this.v | 0; }
        isNull() { return this.v === 0; }
        readByteArray(n) { readByteCalls++; return Uint8Array.from(sslMem.subarray(0, n)).buffer; }
    }
    let observerAdded = null;
    const sslCtx = vm.createContext({
        Process: {
            arch: 'x64', pointerSize: 8, mainModule: {name: 'nginx.exe'},
            getModuleByName: () => ({getExportByName: () => new SSLPtr(0x9000)}),
            attachModuleObserver: obs => { observerAdded = obs.onAdded; return {detach() {}}; }
        },
        NativeFunction: function () { return () => 42; },
        Socket: {
            localAddress: () => { localAddrCalls++; return {ip: '127.0.0.1', port: 443}; },
            peerAddress: () => ({ip: '192.0.2.9', port: 51000})
        },
        Interceptor: {attach: (addr, cb) => { sslHooks.set(addr.toString(), cb); return {detach() {}}; }, flush() {}},
        ptr: v => new SSLPtr(Number(v)),
        send() {}, rpc: {}, setInterval() { return 1; }, clearInterval() {}, setTimeout() { return 1; }, clearTimeout() {}
    });
    vm.runInContext(opensslSource, sslCtx);
    const exportsMap = {SSL_read: 0x1001, SSL_write: 0x1002, SSL_get_fd: 0x1003};
    observerAdded({name: 'libssl-3-x64.dll', path: 'C:\\libssl-3-x64.dll', findExportByName: n => exportsMap[n] ? new SSLPtr(exportsMap[n]) : null});
    readByteCalls = 0; // ignore initial 16-byte prologue snapshots
    const writeHook = sslHooks.get('0x1002');
    const c1 = {};
    writeHook.onEnter.call(c1, [new SSLPtr(0xabc0), new SSLPtr(0x2000), new SSLPtr(100000)]);
    writeHook.onLeave.call(c1, new SSLPtr(-1)); // WANT_WRITE: must not copy buffer
    assert.equal(readByteCalls, 0);

    const c2 = {};
    writeHook.onEnter.call(c2, [new SSLPtr(0xabc0), new SSLPtr(0x2000), new SSLPtr(100000)]);
    writeHook.onLeave.call(c2, new SSLPtr(100000));
    assert.equal(localAddrCalls, 1); // endpoint cached after first lookup!
    const events = vm.runInContext('events', sslCtx);
    assert.equal(events.length, 1);
    assert.equal(events[0].data.byteLength, 100000); // > 65536 not truncated!
    assert.equal(events[0].event.incomplete, false);
}
console.log('IIS completion recovery regression tests passed');
