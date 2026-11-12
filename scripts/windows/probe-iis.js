'use strict';

// This feasibility probe records call metadata only. Pending operations are never
// read before completion and their buffers are never represented as plaintext.
const apiNames = ['HttpReceiveHttpRequest', 'HttpReceiveRequestEntityBody',
    'HttpSendHttpResponse', 'HttpSendResponseEntityBody',
    'UlAtqReceiveEntityBody', 'UlAtqSendEntityBody', 'UlAtqSendHttpResponse'];
const listeners = [];
const attached = new Set();
let events = [];
let dropped = 0;
const counts = {};

function record(event) {
    if (events.length < 256) events.push(event);
    else dropped++;
}

function inspect(module) {
    const name = module.name.toLowerCase();
    if (name !== 'httpapi.dll' && name !== 'w3dt.dll' && name !== 'iiscore.dll') return;
    const exports = module.enumerateExports().filter(e => /http|receive|send/i.test(e.name));
    record({type: 'module', name: module.name, path: module.path,
        exports: exports.slice(0, 128).map(e => e.name)});
    for (const api of apiNames) {
        const address = module.findExportByName(api);
        if (address === null || attached.has(address.toString())) continue;
        attached.add(address.toString());
        const publicApi = api.startsWith('Http');
        counts[api] = publicApi ? {calls: 0, success: 0, pending: 0, errors: 0}
            : {calls: 0, returns_zero: 0, returns_nonzero: 0};
        listeners.push(Interceptor.attach(address, {
            onEnter(args) {
                counts[api].calls++;
                this.request = args[1].toString();
                this.caller = DebugSymbol.fromAddress(this.returnAddress).toString();
            },
            onLeave(result) {
                const status = result.toUInt32();
                if (publicApi) {
                    if (status === 0) counts[api].success++;
                    else if (status === 997) counts[api].pending++;
                    else counts[api].errors++;
                } else if (status === 0) counts[api].returns_zero++;
                else counts[api].returns_nonzero++;
                record({type: 'call', api, argument_1: this.request,
                    return_value: status, caller: this.caller});
            }
        }));
        record({type: 'hook', api, address: address.toString()});
    }
}

const observer = Process.attachModuleObserver({onAdded: inspect});
record({type: 'ready', pid: Process.id, arch: Process.arch,
    modules: Process.enumerateModules().map(m => m.name)});
const timer = setInterval(() => {
    if (events.length > 0 || dropped > 0) {
        send({type: 'batch', events, dropped});
        events = [];
        dropped = 0;
    }
}, 250);

rpc.exports = {
    finish() {
        observer.detach();
        for (const listener of listeners) listener.detach();
        clearInterval(timer);
        const result = {type: 'summary', counts, events, dropped,
            plaintext_verified: false,
            limitation: 'API metadata experiment; asynchronous completion and complete body reconstruction are unimplemented'};
        events = [];
        return result;
    }
};
