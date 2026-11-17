'use strict';
// Exercise the actual probe with an in-memory public HTTP_REQUEST/OVERLAPPED
// fixture. No IIS private offsets, native calls, or synthetic network service.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, 'iis-plaintext.js'), 'utf8')
    .replace('__REQUEST_LIMIT__', '0').replace('__RESPONSE_LIMIT__', '0').replace('__PORTS__', '[8443]');

function fixture(options = {}) {
    const memory = Buffer.alloc(1 << 20);
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
    const context = vm.createContext({
        Process: {arch: 'x64', pointerSize: 8, findRangeByAddress: () => ({protection: 'r-x'}), enumerateThreads: () => [], getModuleByName: () => ({
            getExportByName: exportedPointer, findExportByName: exportedPointer
        })},
        NativeFunction: function () { return () => new Pointer(0); },
        Interceptor: {attach: (pointer, handler) => { callbacks.set(pointer.toString(), handler); return {detach() {}}; }, flush() {}},
        ptr: value => new Pointer(value), send() {}, rpc: {}, setInterval() {}, clearInterval() {}
    });
    vm.runInContext(source, context);
    const request = allocate(864), overlap = allocate(512), data = string('hello');
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
    return {evaluate, value, memory, u16, u32, u64, request, overlap, data, allocate, exportedPointer, context, callbacks};
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
console.log('IIS completion recovery regression tests passed');
